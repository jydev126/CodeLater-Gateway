"""Anonymous feedback receiver, separate from the authenticated TCP relay.

Expose only through a TLS reverse proxy. No public read/export API, no outbound
messages, no request/body logging. Run `python feedback.py` after configuring
FEEDBACK_DATABASE and a persistent, private writable data directory.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import re
import sqlite3
import time
import uuid
from collections import deque
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from aiohttp import web

MAX_BODY = 64 * 1024
SERVICE_VERSION = 1


class InvalidPayload(ValueError):
    pass


def exact(value, required, optional=()):
    if type(value) is not dict or not set(required) <= value.keys() or value.keys() - set(required) - set(optional):
        raise InvalidPayload()


def string(value, maximum, *, required=False, pattern=None):
    if type(value) is not str or len(value) > maximum or "\x00" in value:
        raise InvalidPayload()
    if required and not value.strip():
        raise InvalidPayload()
    if pattern is not None and re.fullmatch(pattern, value) is None:
        raise InvalidPayload()


def integer(value, minimum, maximum):
    if type(value) is not int or not minimum <= value <= maximum:
        raise InvalidPayload()


def validate(payload):
    exact(payload, {"version", "id", "kind", "description", "details", "contact", "metadata"}, {"diagnostics"})
    if type(payload["version"]) is not int or payload["version"] != SERVICE_VERSION:
        raise InvalidPayload()
    string(payload["id"], 36, required=True)
    try:
        parsed = uuid.UUID(payload["id"])
        if parsed.version != 4 or str(parsed) != payload["id"]:
            raise InvalidPayload()
    except ValueError:
        raise InvalidPayload() from None
    if payload["kind"] not in ("bug", "suggestion"):
        raise InvalidPayload()
    string(payload["description"], 4000, required=True)
    string(payload["details"], 4000)
    string(payload["contact"], 320)
    meta = payload["metadata"]
    exact(meta, {"appVersion", "buildNumber", "androidSdk", "language"})
    string(meta["appVersion"], 32, pattern=r"\d{1,5}\.\d{1,5}\.\d{1,5}(?:[.-][a-zA-Z0-9.-]{1,12})?")
    string(meta["buildNumber"], 12, pattern=r"\d{1,12}")
    integer(meta["androidSdk"], 24, 100)
    if meta["language"] not in ("en", "zh-Hans"):
        raise InvalidPayload()
    if "diagnostics" in payload:
        data = payload["diagnostics"]
        exact(data, {"version", "databaseVersion", "logCounts"})
        if type(data["version"]) is not int or data["version"] != 1:
            raise InvalidPayload()
        integer(data["databaseVersion"], 1, 10000)
        exact(data["logCounts"], {"info", "warning", "error"})
        for count in data["logCounts"].values():
            integer(count, 0, 1000)
    # Re-encode only validated fields. No raw headers or source address persist.
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def decode_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise InvalidPayload()
            result[key] = value
        return result
    return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)


@dataclass(frozen=True)
class Config:
    database: Path
    host: str = "127.0.0.1"
    port: int = 8766
    per_ip_hour: int = 5
    global_hour: int = 100
    max_records: int = 10000
    max_bytes: int = 64 * 1024 * 1024
    max_inflight: int = 16
    read_timeout: float = 10
    trusted_proxies: tuple = ()

    @classmethod
    def from_env(cls):
        database = os.environ.get("FEEDBACK_DATABASE", "")
        if not database or not Path(database).is_absolute():
            raise ValueError()
        def positive(name, default):
            number = int(os.environ.get(name, default))
            if number <= 0:
                raise ValueError()
            return number
        port = positive("FEEDBACK_PORT", 8766)
        if port > 65535:
            raise ValueError()
        host = os.environ.get("FEEDBACK_HOST", "127.0.0.1")
        ipaddress.ip_address(host)
        proxies = tuple(ipaddress.ip_network(s.strip()) for s in os.environ.get("FEEDBACK_TRUSTED_PROXIES", "").split(",") if s.strip())
        return cls(Path(database), host=host, port=port,
                   per_ip_hour=positive("FEEDBACK_PER_IP_HOUR", 5),
                   global_hour=positive("FEEDBACK_GLOBAL_HOUR", 100),
                   max_records=positive("FEEDBACK_MAX_RECORDS", 10000),
                   max_bytes=positive("FEEDBACK_MAX_BYTES", 64 * 1024 * 1024),
                   trusted_proxies=proxies)


class Store:
    def __init__(self, config):
        self.config = config
        config.database.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        # Refuse a silently relocated database or a world-readable old file.
        if config.database.is_symlink():
            raise ValueError()
        fd = os.open(config.database, os.O_CREAT | os.O_RDWR, 0o600)
        os.close(fd)
        os.chmod(config.database, 0o600)
        with self.connect() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript("""
                CREATE TABLE IF NOT EXISTS feedback(
                    id TEXT PRIMARY KEY, digest TEXT NOT NULL,
                    payload TEXT NOT NULL, received_at INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS rate(
                    bucket TEXT NOT NULL, hour INTEGER NOT NULL, count INTEGER NOT NULL,
                    PRIMARY KEY(bucket, hour));
                CREATE TABLE IF NOT EXISTS state(key TEXT PRIMARY KEY, value BLOB NOT NULL);
            """)
            db.execute("INSERT OR IGNORE INTO state VALUES ('salt', ?)", (os.urandom(32),))
            db.execute("INSERT OR IGNORE INTO state VALUES ('bytes', 0)")
            self.salt = db.execute("SELECT value FROM state WHERE key='salt'").fetchone()[0]

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.config.database, timeout=1)
        try:
            db.execute("PRAGMA synchronous=FULL")
            with db:
                yield db
        finally:
            db.close()

    def submit(self, payload, encoded, address, now):
        digest = hashlib.sha256(encoded.encode()).hexdigest()
        hour = int(now) // 3600
        source = hmac.new(self.salt, address.encode(), hashlib.sha256).hexdigest()
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            previous = db.execute("SELECT digest FROM feedback WHERE id=?", (payload["id"],)).fetchone()
            if previous:
                return (200, "received") if hmac.compare_digest(previous[0], digest) else (409, "id_conflict")
            db.execute("DELETE FROM rate WHERE hour < ?", (hour,))
            for bucket, maximum in (("all", self.config.global_hour), (source, self.config.per_ip_hour)):
                row = db.execute("SELECT count FROM rate WHERE bucket=? AND hour=?", (bucket, hour)).fetchone()
                if row and row[0] >= maximum:
                    return 429, "rate_limited"
            size = len(encoded.encode())
            used = int(db.execute("SELECT value FROM state WHERE key='bytes'").fetchone()[0])
            count = db.execute("SELECT count(*) FROM feedback").fetchone()[0]
            if used + size > self.config.max_bytes or count >= self.config.max_records:
                return 503, "storage_full"
            db.execute("INSERT INTO feedback VALUES (?,?,?,?)", (payload["id"], digest, encoded, int(now)))
            db.execute("UPDATE state SET value=? WHERE key='bytes'", (used + size,))
            for bucket in ("all", source):
                db.execute("INSERT INTO rate VALUES (?,?,1) ON CONFLICT(bucket,hour) DO UPDATE SET count=count+1", (bucket, hour))
        return 201, "received"


class Attempts:
    """Bound request work even for invalid bodies; never trust forwarded IPs."""
    def __init__(self):
        self.global_times = deque()
        self.sources = {}

    def allow(self, source, now):
        for times in (self.global_times,):
            while times and times[0] <= now - 60:
                times.popleft()
        if len(self.global_times) >= 120:
            return False
        self.global_times.append(now)
        self.sources = {key: times for key, times in self.sources.items() if times and times[-1] > now - 60}
        if source not in self.sources and len(self.sources) >= 2048:
            return False
        times = self.sources.setdefault(source, deque())
        while times and times[0] <= now - 60:
            times.popleft()
        if len(times) >= 30:
            return False
        times.append(now)
        return True


def client_address(request, config):
    address = ipaddress.ip_address(request.remote or "127.0.0.1")
    # The trusted immediate proxy must overwrite X-Real-IP with $remote_addr.
    if any(address in network for network in config.trusted_proxies):
        forwarded = request.headers.getall("X-Real-IP", [])
        if len(forwarded) == 1 and len(forwarded[0]) <= 45:
            try:
                address = ipaddress.ip_address(forwarded[0])
            except ValueError:
                pass
    return str(address)


def create_app(config, *, now=time.time, monotonic=time.monotonic, store=None):
    store = store or Store(config)
    attempts = Attempts()
    inflight = 0

    def reply(status, code, identifier=None):
        body = {"version": SERVICE_VERSION, "status": code}
        if identifier is not None:
            body["id"] = identifier
        headers = {"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"}
        if status == 429:
            headers["Retry-After"] = "3600"
        return web.json_response(body, status=status, headers=headers)

    async def receive(request):
        nonlocal inflight
        if inflight >= config.max_inflight:
            return reply(503, "busy")
        inflight += 1
        try:
            address = client_address(request, config)
            if not attempts.allow(address, monotonic()):
                return reply(429, "rate_limited")
            if request.query_string or request.headers.get("Origin"):
                return reply(400, "invalid_request")
            if (request.content_type != "application/json" or
                    request.charset not in (None, "utf-8") or
                    request.headers.get("Content-Encoding", "identity") != "identity"):
                return reply(415, "unsupported_media")
            async with asyncio.timeout(config.read_timeout):
                raw = await request.read()
            payload = decode_json(raw)
            encoded = validate(payload)
            if request.headers.getall("Idempotency-Key", []) != [payload["id"]]:
                return reply(400, "invalid_request")
            status, code = await asyncio.to_thread(store.submit, payload, encoded, address, now())
            return reply(status, code, payload["id"] if code == "received" else None)
        except web.HTTPRequestEntityTooLarge:
            return reply(413, "too_large")
        except (InvalidPayload, ValueError, TypeError, UnicodeError, RecursionError):
            return reply(400, "invalid_request")
        except (TimeoutError, ConnectionError):
            return reply(408, "request_timeout")
        except Exception:
            # Never echo SQLite errors, paths, headers, or user-entered content.
            return reply(503, "unavailable")
        finally:
            inflight -= 1

    async def health(_):
        return web.json_response({"service": "codelater-feedback", "version": SERVICE_VERSION}, headers={"Cache-Control": "no-store"})

    app = web.Application(client_max_size=MAX_BODY, handler_args={
        "auto_decompress": False, "max_headers": 32,
        "max_line_size": 4096, "max_field_size": 4096,
    })
    app.router.add_post("/v1/feedback", receive)
    app.router.add_get("/healthz", health)
    return app


def main():
    os.umask(0o077)
    # Parser failures must not dump request lines/headers into application logs.
    logging.getLogger("aiohttp.server").disabled = True
    try:
        config = Config.from_env()
        app = create_app(config)
    except Exception:
        raise SystemExit("Feedback configuration or storage unavailable") from None
    web.run_app(app, host=config.host, port=config.port, access_log=None,
                print=None, shutdown_timeout=10)


if __name__ == "__main__":
    main()
