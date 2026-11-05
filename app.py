"""A small authenticated WebSocket-to-TCP relay. No application protocol parsing."""

import asyncio
import base64
import binascii
from collections import Counter, deque
from dataclasses import dataclass, field
from http import HTTPStatus
import ipaddress
import json
import logging
import math
import os
from pathlib import Path
import secrets
import signal
import time

from websockets.asyncio.server import serve
from websockets.exceptions import ConnectionClosed


SUBPROTOCOL = "codelater-tunnel-v1"
CONTROL_LIMIT = 2048
MESSAGE_LIMIT = 1024 * 1024
AUTH_TRACK_LIMIT = 10000
LOG = logging.getLogger("codelater.gateway")
# Library debug logs can contain Authorization and payloads. Never forward them.
WIRE_LOG = logging.Logger("codelater.gateway.wire", level=logging.CRITICAL + 1)
WIRE_LOG.addHandler(logging.NullHandler())
WIRE_LOG.propagate = False


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class Config:
    password: bytes = field(repr=False)
    allowed_cidrs: tuple
    allowed_ports: frozenset
    listen_host: str = "0.0.0.0"
    listen_port: int = 8765
    connect_timeout: float = 5
    handshake_timeout: float = 5
    max_connections: int = 8
    max_per_ip: int = 4
    auth_fail_limit: int = 5
    auth_window: float = 300
    auth_block: float = 900
    idle_timeout: float = 1800
    trust_proxy: bool = False
    trusted_proxies: tuple = ()
    allow_origin: str = ""

    @classmethod
    def from_env(cls, env=None):
        env = os.environ if env is None else env

        def positive(name, default, kind=float):
            try:
                value = kind(env.get(name, default))
                if value <= 0 or not math.isfinite(value):
                    raise ValueError
                return value
            except (ValueError, TypeError, OverflowError):
                raise ConfigError(f"{name} must be a finite positive {kind.__name__}") from None

        def networks(name):
            try:
                return tuple(ipaddress.ip_network(v.strip())
                             for v in env.get(name, "").split(",") if v.strip())
            except ValueError:
                raise ConfigError(f"{name} must contain valid CIDRs") from None

        # A configured file always takes priority; never fall back on file error.
        if "GATEWAY_PASSWORD_FILE" in env:
            try:
                password = Path(env["GATEWAY_PASSWORD_FILE"]).read_text(encoding="utf-8").rstrip("\r\n")
            except (OSError, ValueError, UnicodeError):
                raise ConfigError("GATEWAY_PASSWORD_FILE cannot be read") from None
        else:
            password = env.get("GATEWAY_PASSWORD", "")
        if not password.strip() or password.strip().upper() == "CHANGE_ME":
            raise ConfigError("GATEWAY_PASSWORD must be nonempty and must not be CHANGE_ME")
        if "\r" in password or "\n" in password:
            raise ConfigError("GATEWAY_PASSWORD must be a single line")
        cidrs = networks("ALLOWED_TARGET_CIDRS")
        if not cidrs:
            raise ConfigError("ALLOWED_TARGET_CIDRS must explicitly allow at least one CIDR")
        try:
            ports = frozenset(int(v.strip()) for v in env.get("ALLOWED_TARGET_PORTS", "22").split(","))
            if not ports or any(not 1 <= p <= 65535 for p in ports):
                raise ValueError
        except ValueError:
            raise ConfigError("ALLOWED_TARGET_PORTS must contain ports in 1..65535") from None
        port = positive("LISTEN_PORT", 8765, int)
        if port > 65535:
            raise ConfigError("LISTEN_PORT must be in 1..65535")
        host = env.get("LISTEN_HOST", "0.0.0.0").strip()
        try:
            ipaddress.ip_address(host)
        except ValueError:
            raise ConfigError("LISTEN_HOST must be an IP literal") from None
        proxy = env.get("TRUST_PROXY_HEADERS", "false").lower()
        if proxy not in ("true", "false"):
            raise ConfigError("TRUST_PROXY_HEADERS must be true or false")
        trusted = networks("TRUSTED_PROXY_CIDRS")
        if proxy == "true" and not trusted:
            raise ConfigError("TRUSTED_PROXY_CIDRS is required when trusting proxy headers")
        origin = env.get("ALLOW_ORIGIN", "").strip()
        if origin == "*" or "\n" in origin or "\r" in origin:
            raise ConfigError("ALLOW_ORIGIN must be one exact Origin, not a wildcard")
        return cls(
            password=password.encode("utf-8"), allowed_cidrs=cidrs, allowed_ports=ports,
            listen_host=host, listen_port=port,
            connect_timeout=positive("CONNECT_TIMEOUT_SECONDS", 5),
            handshake_timeout=positive("TARGET_HANDSHAKE_TIMEOUT_SECONDS", 5),
            max_connections=positive("MAX_CONNECTIONS", 8, int),
            max_per_ip=positive("MAX_CONNECTIONS_PER_IP", 4, int),
            auth_fail_limit=positive("AUTH_FAIL_LIMIT", 5, int),
            auth_window=positive("AUTH_FAIL_WINDOW_SECONDS", 300),
            auth_block=positive("AUTH_BLOCK_SECONDS", 900),
            idle_timeout=positive("IDLE_TIMEOUT_SECONDS", 1800),
            trust_proxy=proxy == "true", trusted_proxies=trusted, allow_origin=origin,
        )


def in_networks(address, networks):
    return any(address in network for network in networks)


def single_header(headers, name):
    values = headers.get_all(name)
    return values[0] if len(values) == 1 else None


def client_ip(peer, headers, config):
    address = ipaddress.ip_address(peer[0])
    if not config.trust_proxy or not in_networks(address, config.trusted_proxies):
        return str(address)
    forwarded = single_header(headers, "X-Forwarded-For")
    if not forwarded:
        return str(address)
    try:
        parts = forwarded.split(",")
        if len(parts) > 32 or "%" in forwarded:
            return str(address)
        chain = [ipaddress.ip_address(p.strip()) for p in parts]
    except ValueError:
        return str(address)
    # Walk from the trusted socket peer, stopping at the nearest untrusted hop.
    # A client-supplied leftmost IP cannot bypass the rate limit.
    for hop in reversed(chain):
        if not in_networks(address, config.trusted_proxies):
            break
        address = hop
    return str(address)


def authorized(headers, password):
    value = single_header(headers, "Authorization")
    try:
        scheme, encoded = value.split(" ", 1)
        if scheme.lower() != "basic":
            return False
        decoded = base64.b64decode(encoded, validate=True)
        username, supplied = decoded.split(b":", 1)
    except (AttributeError, ValueError, binascii.Error):
        return False
    matches = secrets.compare_digest(supplied, password)
    return username == b"codelater" and matches


class AuthLimiter:
    """Bounded in-memory failure records; full capacity fails closed temporarily."""

    def __init__(self, config, clock=time.monotonic):
        self.config = config
        self.clock = clock
        self.entries = {}

    def blocked(self, ip):
        now = self.clock()
        # No background task and no permanent records for expired source IPs.
        for key, (failures, until) in list(self.entries.items()):
            if until <= now and (until or not failures or failures[-1] <= now - self.config.auth_window):
                del self.entries[key]
        entry = self.entries.get(ip)
        return bool(entry and entry[1] > now) or (entry is None and len(self.entries) >= AUTH_TRACK_LIMIT)

    def failed(self, ip):
        now = self.clock()
        failures, _ = self.entries.get(ip, (deque(maxlen=self.config.auth_fail_limit), 0))
        while failures and failures[0] <= now - self.config.auth_window:
            failures.popleft()
        failures.append(now)
        until = now + self.config.auth_block if len(failures) >= self.config.auth_fail_limit else 0
        self.entries[ip] = (failures, until)


class TunnelError(Exception):
    def __init__(self, code, close_code=1008):
        self.code = code
        self.close_code = close_code


async def read_target(websocket, config):
    message = ""
    size = 0
    try:
        async with asyncio.timeout(config.handshake_timeout):
            async for fragment in websocket.recv_streaming():
                if not isinstance(fragment, str):
                    raise TunnelError("bad_request")
                size += len(fragment.encode("utf-8"))
                if size > CONTROL_LIMIT:
                    raise TunnelError("bad_request")
                message += fragment
        data = json.loads(message)
        if not isinstance(data, dict) or type(data.get("version")) is not int or data["version"] != 1:
            raise ValueError
        host, port = data.get("host"), data.get("port")
        if not isinstance(host, str) or "%" in host or type(port) is not int or not 1 <= port <= 65535:
            raise ValueError
        address = ipaddress.ip_address(host)
    except (ValueError, TypeError, RecursionError, TimeoutError):
        raise TunnelError("bad_request") from None
    if not in_networks(address, config.allowed_cidrs) or port not in config.allowed_ports:
        raise TunnelError("target_denied")
    return str(address), port


async def send_error(websocket, code):
    await websocket.send(json.dumps({"version": 1, "ok": False, "code": code}))


async def relay(websocket, reader, writer, idle_timeout, stats):
    last_activity = time.monotonic()

    async def ws_to_tcp():
        nonlocal last_activity
        async for message in websocket:
            if not isinstance(message, bytes):
                raise TunnelError("protocol_error", 1002)
            writer.write(message)
            await writer.drain()
            stats[0] += len(message)
            if message:
                last_activity = time.monotonic()

    async def tcp_to_ws():
        nonlocal last_activity
        while data := await reader.read(65536):
            await websocket.send(data)
            stats[1] += len(data)
            last_activity = time.monotonic()

    async def idle_watch():
        while True:
            remaining = idle_timeout - (time.monotonic() - last_activity)
            if remaining <= 0:
                raise TunnelError("idle_timeout", 1001)
            await asyncio.sleep(remaining)

    tasks = [asyncio.create_task(coro, name=f"gateway:{name}") for name, coro in (
        ("ws-to-tcp", ws_to_tcp()), ("tcp-to-ws", tcp_to_ws()), ("idle", idle_watch()))]
    try:
        done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            task.result()
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


class Gateway:
    def __init__(self, config):
        self.config = config
        self.limiter = AuthLimiter(config)
        self.active = 0
        self.per_ip = Counter()

    def process_request(self, connection, request):
        if request.path == "/healthz":
            return connection.respond(HTTPStatus.OK, "ok\n")
        if request.path != "/v1/tunnel":
            return connection.respond(HTTPStatus.NOT_FOUND, "not found\n")
        ip = client_ip(connection.remote_address, request.headers, self.config)
        if self.limiter.blocked(ip):
            return connection.respond(HTTPStatus.TOO_MANY_REQUESTS, "rate limited\n")
        if not authorized(request.headers, self.config.password):
            self.limiter.failed(ip)
            LOG.warning("auth failed client_ip=%s", ip)
            response = connection.respond(HTTPStatus.UNAUTHORIZED, "unauthorized\n")
            response.headers["WWW-Authenticate"] = 'Basic realm="codelater-gateway", charset="UTF-8"'
            return response
        origins = request.headers.get_all("Origin")
        if len(origins) > 1 or (origins and origins[0] and origins[0] != self.config.allow_origin):
            return connection.respond(HTTPStatus.FORBIDDEN, "origin denied\n")
        protocols = single_header(request.headers, "Sec-WebSocket-Protocol")
        if not protocols or SUBPROTOCOL not in [p.strip() for p in protocols.split(",")]:
            return connection.respond(HTTPStatus.BAD_REQUEST, "subprotocol required\n")
        return None

    async def handler(self, websocket):
        ip = client_ip(websocket.remote_address, websocket.request.headers, self.config)
        if self.active >= self.config.max_connections or self.per_ip[ip] >= self.config.max_per_ip:
            LOG.info("connection rejected client_ip=%s category=busy", ip)
            try:
                await send_error(websocket, "busy")
            except ConnectionClosed:
                pass
            finally:
                await websocket.close(1013, "busy")
            return
        # No await between checking and reserving; includes target handshake time.
        self.active += 1
        self.per_ip[ip] += 1
        session = asyncio.create_task(self.session(websocket, ip), name="gateway:session")
        closed = asyncio.create_task(websocket.wait_closed(), name="gateway:closed")
        try:
            await asyncio.wait((session, closed), return_when=asyncio.FIRST_COMPLETED)
        finally:
            # Also cancels pending TCP connects immediately when the WS disappears.
            for task in (session, closed):
                if not task.done():
                    task.cancel()
            await asyncio.gather(session, closed, return_exceptions=True)
            self.active -= 1
            self.per_ip[ip] -= 1
            if not self.per_ip[ip]:
                del self.per_ip[ip]

    async def session(self, websocket, ip):
        started = time.monotonic()
        host, port, writer = "-", "-", None
        stats = [0, 0]
        ready = False
        category = "closed"
        close_code = 1000
        LOG.info("connection accepted client_ip=%s", ip)
        try:
            host, port = await read_target(websocket, self.config)
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port), timeout=self.config.connect_timeout)
            except (OSError, TimeoutError):
                raise TunnelError("target_unreachable") from None
            await websocket.send(json.dumps({"version": 1, "ok": True}))
            ready = True
            LOG.info("target connected client_ip=%s target_ip=%s target_port=%s", ip, host, port)
            await relay(websocket, reader, writer, self.config.idle_timeout, stats)
        except ConnectionClosed:
            category = "websocket_closed"
        except asyncio.CancelledError:
            category = "cancelled"
            raise
        except Exception as error:
            category = error.code if isinstance(error, TunnelError) else "internal_error"
            close_code = error.close_code if isinstance(error, TunnelError) else 1011
            if not ready:
                try:
                    await send_error(websocket, category)
                except ConnectionClosed:
                    pass
        finally:
            async def cleanup():
                if writer is not None:
                    writer.close()
                    try:
                        await asyncio.wait_for(writer.wait_closed(), timeout=5)
                    except (OSError, TimeoutError):
                        writer.transport.abort()
                await websocket.close(close_code, category)
                LOG.info(
                    "connection closed client_ip=%s target_ip=%s target_port=%s duration=%.3f "
                    "bytes_phone_to_target=%d bytes_target_to_phone=%d category=%s",
                    ip, host, port, time.monotonic() - started, *stats, category)

            # wait_closed may wake the handler while this finally is executing.
            # Cancellation must not interrupt TCP cleanup or the closing log.
            closing = asyncio.create_task(cleanup(), name="gateway:cleanup")
            try:
                await asyncio.shield(closing)
            except asyncio.CancelledError:
                await closing
                raise

    def server(self, **overrides):
        options = dict(host=self.config.listen_host, port=self.config.listen_port,
                       subprotocols=[SUBPROTOCOL], process_request=self.process_request,
                       compression=None, max_size=MESSAGE_LIMIT, max_queue=4,
                       write_limit=32768, ping_interval=25, ping_timeout=20,
                       open_timeout=5, close_timeout=5, server_header=None, logger=WIRE_LOG)
        options.update(overrides)
        return serve(self.handler, **options)


async def main(config):
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)
    async with Gateway(config).server():
        LOG.info("gateway started")
        await stop.wait()
    LOG.info("gateway stopped")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    try:
        config = Config.from_env()
    except ConfigError as error:
        LOG.error("configuration error: %s", error)
        raise SystemExit(1) from None
    try:
        asyncio.run(main(config))
    except OSError:
        LOG.error("gateway startup failed: listen unavailable")
        raise SystemExit(1) from None
