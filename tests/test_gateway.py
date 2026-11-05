import asyncio
import base64
from contextlib import asynccontextmanager
import json
import logging
import os
import subprocess
import sys

import pytest
from websockets.asyncio.client import connect
from websockets.datastructures import Headers
from websockets.exceptions import ConnectionClosed, InvalidStatus

import app


PASSWORD = "test-only:随机-password-123456"


def basic(password=PASSWORD, username="codelater"):
    return "Basic " + base64.b64encode(f"{username}:{password}".encode()).decode()


def config(**values):
    return app.Config.from_env({
        "GATEWAY_PASSWORD": PASSWORD,
        "ALLOWED_TARGET_CIDRS": "127.0.0.0/8,::1/128",
        "ALLOWED_TARGET_PORTS": "22",
        **values,
    })


@pytest.fixture
async def gateway_factory():
    @asynccontextmanager
    async def factory(cfg=None):
        gateway = app.Gateway(cfg or config())
        async with gateway.server(host="127.0.0.1", port=0) as server:
            port = server.sockets[0].getsockname()[1]
            yield gateway, f"ws://127.0.0.1:{port}/v1/tunnel"
        assert gateway.active == 0
        assert not gateway.per_ip
        assert not [t for t in asyncio.all_tasks() if t.get_name().startswith("gateway:")]
    return factory


def dial(url, **kwargs):
    options = dict(subprotocols=[app.SUBPROTOCOL], additional_headers={"Authorization": basic()},
                   compression=None, proxy=None, close_timeout=1)
    options.update(kwargs)
    return connect(url, **options)


async def target(ws, host="127.0.0.1", port=22):
    await ws.send(json.dumps({"version": 1, "host": host, "port": port}))
    return json.loads(await asyncio.wait_for(ws.recv(), 2))


async def error_response(ws, code):
    assert json.loads(await asyncio.wait_for(ws.recv(), 2)) == {
        "version": 1, "ok": False, "code": code}
    await asyncio.wait_for(ws.wait_closed(), 2)


@pytest.fixture
async def echo():
    connections = set()
    ended = asyncio.Event()
    async def handle(reader, writer):
        task = asyncio.current_task()
        connections.add(task)
        try:
            while data := await reader.read(65536):
                writer.write(data)
                await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()
            connections.remove(task)
            ended.set()
    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    async with server:
        yield port, ended
    for task in list(connections):
        task.cancel()
    await asyncio.gather(*connections, return_exceptions=True)


@pytest.mark.parametrize("value", ["", " ", "CHANGE_ME", "change_me", "a\nb"])
def test_password_rejected(value):
    with pytest.raises(app.ConfigError, match="GATEWAY_PASSWORD"):
        config(GATEWAY_PASSWORD=value)


def test_no_password_startup_rejected():
    env = {k: v for k, v in os.environ.items() if not k.startswith("GATEWAY_PASSWORD")}
    result = subprocess.run([sys.executable, "app.py"], env=env, capture_output=True, timeout=5)
    assert result.returncode == 1
    assert b"configuration error" in result.stderr
    assert b"Traceback" not in result.stderr


def test_password_file_precedence(tmp_path):
    file = tmp_path / "password"
    file.write_text(PASSWORD + "\n", encoding="utf-8")
    cfg = config(GATEWAY_PASSWORD="CHANGE_ME", GATEWAY_PASSWORD_FILE=str(file))
    assert cfg.password == PASSWORD.encode()
    assert PASSWORD not in repr(cfg)
    file.write_text("")
    with pytest.raises(app.ConfigError):
        config(GATEWAY_PASSWORD_FILE=str(file))
    with pytest.raises(app.ConfigError, match="cannot be read"):
        config(GATEWAY_PASSWORD_FILE=str(tmp_path / "missing"))


@pytest.mark.parametrize("key,value", [
    ("ALLOWED_TARGET_CIDRS", ""), ("ALLOWED_TARGET_CIDRS", "oops"),
    ("ALLOWED_TARGET_PORTS", "0"), ("ALLOWED_TARGET_PORTS", "65536"),
    ("ALLOWED_TARGET_PORTS", "22,no"), ("ALLOWED_TARGET_PORTS", ""),
    ("LISTEN_PORT", "65536"), ("LISTEN_HOST", "localhost"),
    ("CONNECT_TIMEOUT_SECONDS", "0"), ("CONNECT_TIMEOUT_SECONDS", "nan"),
    ("IDLE_TIMEOUT_SECONDS", "inf"), ("TARGET_HANDSHAKE_TIMEOUT_SECONDS", "-1"),
    ("MAX_CONNECTIONS", "0"), ("MAX_CONNECTIONS_PER_IP", "1.5"),
    ("AUTH_FAIL_LIMIT", "0"), ("AUTH_FAIL_WINDOW_SECONDS", "-1"),
    ("AUTH_BLOCK_SECONDS", "0"), ("TRUST_PROXY_HEADERS", "yes"),
    ("TRUST_PROXY_HEADERS", "true"), ("TRUSTED_PROXY_CIDRS", "nope"),
    ("ALLOW_ORIGIN", "*"),
])
def test_config_validation(key, value):
    with pytest.raises(app.ConfigError):
        config(**{key: value})


@pytest.mark.parametrize("headers", [
    {"Authorization": basic("wrong")}, {"Authorization": basic(username="wrong")},
    {}, {"Authorization": "Basic ???"}, {"Authorization": "Bearer nope"},
    {"Authorization": "Basic " + base64.b64encode(b"no-colon").decode()},
    [("Authorization", basic()), ("Authorization", basic())],
])
async def test_invalid_auth_401(gateway_factory, headers):
    async with gateway_factory() as (_, url):
        with pytest.raises(InvalidStatus) as error:
            async with dial(url, additional_headers=headers):
                pytest.fail("upgraded invalid auth")
        assert error.value.response.status_code == 401
        assert "Basic" in error.value.response.headers["WWW-Authenticate"]
        assert PASSWORD.encode() not in error.value.response.body


async def test_valid_auth_constant_time_no_secrets(gateway_factory, monkeypatch, caplog):
    calls = []
    original = app.secrets.compare_digest
    def compare(a, b):
        calls.append((a, b))
        return original(a, b)
    monkeypatch.setattr(app.secrets, "compare_digest", compare)
    with caplog.at_level(logging.DEBUG):
        async with gateway_factory() as (_, url):
            # Client library logging is unrelated to server redaction.
            client_log = logging.Logger("test-client", level=100)
            async with dial(url, logger=client_log) as ws:
                assert ws.subprotocol == app.SUBPROTOCOL
                assert "Sec-WebSocket-Extensions" not in ws.response.headers
            with pytest.raises(InvalidStatus):
                async with dial(url, logger=client_log,
                                additional_headers={"Authorization": basic("wrong-secret")}):
                    pass
    assert calls == [(PASSWORD.encode(), PASSWORD.encode()), (b"wrong-secret", PASSWORD.encode())]
    assert "auth failed client_ip=127.0.0.1" in caplog.text
    for value in (PASSWORD, basic(), "wrong-secret", "Authorization"):
        assert value not in caplog.text


@pytest.mark.parametrize("path", ["/", "/other", "/v1/tunnel/", "/v1/tunnel?foo=bar"])
async def test_wrong_path_404(gateway_factory, path):
    async with gateway_factory() as (_, url):
        with pytest.raises(InvalidStatus) as error:
            async with dial(url.replace("/v1/tunnel", path)):
                pass
        assert error.value.response.status_code == 404


@pytest.mark.parametrize("protocols", [[], ["wrong"]])
async def test_wrong_subprotocol(gateway_factory, protocols):
    async with gateway_factory() as (_, url):
        with pytest.raises(InvalidStatus) as error:
            async with dial(url, subprotocols=protocols):
                pass
        assert error.value.response.status_code == 400


@pytest.mark.parametrize("message", [
    "{", "[]", "null", b"binary", "x" * 2049,
    json.dumps({"version": 2, "host": "127.0.0.1", "port": 22}),
    json.dumps({"version": True, "host": "127.0.0.1", "port": 22}),
    json.dumps({"version": 1.0, "host": "127.0.0.1", "port": 22}),
    *[json.dumps({"version": 1, "host": host, "port": port}) for host, port in [
        ("example.com", 22), ("dev.local", 22), ("127.0.0.1", "22"),
        ("127.0.0.1", True), ("127.0.0.1", 0), ("127.0.0.1", 65536),
        ("127.0.0.1", 22.0), ("::1%eth0", 22), (None, 22), (123, 22)]],
])
async def test_bad_initial_message(gateway_factory, message):
    async with gateway_factory() as (_, url):
        async with dial(url) as ws:
            await ws.send(message)
            await error_response(ws, "bad_request")


async def test_fragmented_control_limit_is_utf8_bytes(gateway_factory):
    async with gateway_factory() as (_, url):
        async with dial(url) as ws:
            await ws.send(["界" * 400, "界" * 400])
            await error_response(ws, "bad_request")


async def test_target_handshake_timeout(gateway_factory):
    async with gateway_factory(config(TARGET_HANDSHAKE_TIMEOUT_SECONDS="0.05")) as (_, url):
        async with dial(url) as ws:
            await error_response(ws, "bad_request")


@pytest.mark.parametrize("host,port", [("192.0.2.1", 22), ("127.0.0.1", 2222), ("2001:db8::1", 22)])
async def test_target_denied_without_connect(gateway_factory, monkeypatch, host, port):
    async def forbidden(*args):
        pytest.fail("denied target connected")
    monkeypatch.setattr(app.asyncio, "open_connection", forbidden)
    async with gateway_factory() as (_, url):
        async with dial(url) as ws:
            assert (await target(ws, host, port))["code"] == "target_denied"


async def test_ipv6_literal_control():
    class Ws:
        async def recv_streaming(self):
            yield '{"version":1,"host":"0:0:0:0:0:0:0:1","port":22}'
    assert await app.read_target(Ws(), config()) == ("::1", 22)


async def test_unreachable(gateway_factory):
    server = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    server.close()
    await server.wait_closed()
    async with gateway_factory(config(ALLOWED_TARGET_PORTS=str(port))) as (_, url):
        async with dial(url) as ws:
            assert await target(ws, port=port) == {"version": 1, "ok": False, "code": "target_unreachable"}


async def test_connect_timeout(gateway_factory, monkeypatch):
    cancelled = asyncio.Event()
    async def slow_connect(*args):
        try:
            await asyncio.Event().wait()
        finally:
            cancelled.set()
    monkeypatch.setattr(app.asyncio, "open_connection", slow_connect)
    async with gateway_factory(config(CONNECT_TIMEOUT_SECONDS="0.05")) as (_, url):
        async with dial(url) as ws:
            assert (await target(ws))["code"] == "target_unreachable"
            assert cancelled.is_set()


async def test_internal_error_redacted(gateway_factory, monkeypatch, caplog):
    async def broken(*args):
        raise RuntimeError(PASSWORD + "/private/path")
    monkeypatch.setattr(app.asyncio, "open_connection", broken)
    async with gateway_factory() as (_, url):
        async with dial(url) as ws:
            assert await target(ws) == {"version": 1, "ok": False, "code": "internal_error"}
            await ws.wait_closed()
            assert ws.close_reason == "internal_error"
    assert PASSWORD not in caplog.text
    assert "/private/path" not in caplog.text


async def receive_bytes(ws, length):
    data = bytearray()
    async with asyncio.timeout(5):
        while len(data) < length:
            chunk = await ws.recv()
            assert isinstance(chunk, bytes)
            data.extend(chunk)
    return bytes(data)


async def test_bidirectional_binary_byte_order(gateway_factory, echo, caplog):
    port, ended = echo
    payload = bytes(range(256)) * 4096 + b"\x00\xfflast"
    with caplog.at_level(logging.INFO, logger=app.LOG.name):
        async with gateway_factory(config(ALLOWED_TARGET_PORTS=str(port))) as (_, url):
            async with dial(url) as ws:
                assert await target(ws, port=port) == {"version": 1, "ok": True}
                # Multiple WS messages and TCP read boundaries must not affect order.
                receive = asyncio.create_task(receive_bytes(ws, len(payload)))
                for offset in range(0, len(payload), 131071):
                    await ws.send(payload[offset:offset + 131071])
                assert await receive == payload
            await asyncio.wait_for(ended.wait(), 2)
    assert f"bytes_phone_to_target={len(payload)}" in caplog.text
    assert f"bytes_target_to_phone={len(payload)}" in caplog.text


async def test_tcp_sends_before_client_data_and_eof(gateway_factory):
    async def handle(reader, writer):
        writer.write(b"target-speaks-first")
        await writer.drain()
        writer.close()
        await writer.wait_closed()
    async with await asyncio.start_server(handle, "127.0.0.1", 0) as server:
        port = server.sockets[0].getsockname()[1]
        async with gateway_factory(config(ALLOWED_TARGET_PORTS=str(port))) as (_, url):
            async with dial(url) as ws:
                assert (await target(ws, port=port))["ok"] is True
                assert await ws.recv() == b"target-speaks-first"
                await asyncio.wait_for(ws.wait_closed(), 2)
                assert ws.close_code == 1000


async def test_text_after_established(gateway_factory, echo):
    port, ended = echo
    async with gateway_factory(config(ALLOWED_TARGET_PORTS=str(port))) as (_, url):
        async with dial(url) as ws:
            assert (await target(ws, port=port))["ok"] is True
            await ws.send("not binary")
            with pytest.raises(ConnectionClosed):
                await ws.recv()
            assert ws.close_code == 1002
            assert ws.close_reason == "protocol_error"
        await asyncio.wait_for(ended.wait(), 2)


async def test_message_size_limit(gateway_factory, echo):
    port, _ = echo
    async with gateway_factory(config(ALLOWED_TARGET_PORTS=str(port))) as (_, url):
        async with dial(url) as ws:
            await target(ws, port=port)
            await ws.send(b"x" * (app.MESSAGE_LIMIT + 1))
            await asyncio.wait_for(ws.wait_closed(), 2)
            assert ws.close_code == 1009


async def test_ws_close_cancels_pending_connect(gateway_factory, monkeypatch):
    started, cancelled = asyncio.Event(), asyncio.Event()
    async def slow_connect(*args):
        started.set()
        try:
            await asyncio.Event().wait()
        finally:
            cancelled.set()
    monkeypatch.setattr(app.asyncio, "open_connection", slow_connect)
    async with gateway_factory() as (_, url):
        async with dial(url) as ws:
            await ws.send('{"version":1,"host":"127.0.0.1","port":22}')
            await asyncio.wait_for(started.wait(), 2)
        await asyncio.wait_for(cancelled.wait(), 2)


@pytest.mark.parametrize("limits", [{"MAX_CONNECTIONS": "1"}, {"MAX_CONNECTIONS_PER_IP": "1"}])
async def test_connection_limit_includes_initial_handshake(gateway_factory, limits):
    async with gateway_factory(config(**limits)) as (gateway, url):
        async with dial(url):
            async with dial(url) as rejected:
                await error_response(rejected, "busy")
                assert rejected.close_code == 1013
            assert gateway.active == 1
        async with asyncio.timeout(2):
            while gateway.active:
                await asyncio.sleep(0.01)
        async with dial(url) as accepted:
            await accepted.send("{")
            await error_response(accepted, "bad_request")


async def test_per_ip_separate_trusted_sources(gateway_factory):
    cfg = config(MAX_CONNECTIONS_PER_IP="1", TRUST_PROXY_HEADERS="true", TRUSTED_PROXY_CIDRS="127.0.0.1/32")
    async with gateway_factory(cfg) as (gateway, url):
        async with dial(url, additional_headers={"Authorization": basic(), "X-Forwarded-For": "192.0.2.1"}):
            async with dial(url, additional_headers={"Authorization": basic(), "X-Forwarded-For": "192.0.2.2"}):
                assert gateway.active == 2


async def test_failed_auth_rate_limit_and_health(gateway_factory):
    async with gateway_factory() as (gateway, url):
        for _ in range(5):
            with pytest.raises(InvalidStatus) as error:
                async with dial(url, additional_headers={"Authorization": basic("bad")}):
                    pass
            assert error.value.response.status_code == 401
        with pytest.raises(InvalidStatus) as error:
            async with dial(url):
                pass
        assert error.value.response.status_code == 429
        assert gateway.active == 0
        assert b"200 OK" in await http_get(url, "/healthz")


def test_auth_window_block_expiry_and_bounded_memory(monkeypatch):
    clock = [0]
    limiter = app.AuthLimiter(config(), clock=lambda: clock[0])
    limiter.failed("a")
    clock[0] = 301
    assert not limiter.blocked("a")
    assert not limiter.entries
    for _ in range(5):
        limiter.failed("a")
    assert limiter.blocked("a")
    clock[0] += 901
    assert not limiter.blocked("a")
    monkeypatch.setattr(app, "AUTH_TRACK_LIMIT", 2)
    limiter.failed("a")
    limiter.failed("b")
    assert limiter.blocked("c")
    assert len(limiter.entries) == 2


async def http_get(url, path):
    from urllib.parse import urlsplit
    port = urlsplit(url).port
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        writer.write(f"GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".encode())
        await writer.drain()
        return await asyncio.wait_for(reader.read(), 2)
    finally:
        writer.close()
        await writer.wait_closed()


async def test_healthz_without_upgrade_or_auth(gateway_factory):
    async with gateway_factory() as (_, url):
        response = await http_get(url, "/healthz")
        assert b"200 OK" in response
        assert response.endswith(b"ok\n")
        assert b"404 Not Found" in await http_get(url, "/unknown")


@pytest.mark.parametrize("trust,trusted,xff,expected", [
    (False, "127.0.0.1/32", "192.0.2.1", "127.0.0.1"),
    (True, "10.0.0.0/8", "192.0.2.1", "127.0.0.1"),
    (True, "127.0.0.1/32", "192.0.2.1", "192.0.2.1"),
    (True, "127.0.0.1/32", "spoof,192.0.2.1", "127.0.0.1"),
    (True, "127.0.0.1/32", "198.51.100.9,192.0.2.1", "192.0.2.1"),
    (True, "127.0.0.1/32,10.0.0.0/8", "192.0.2.1,10.0.0.2", "192.0.2.1"),
    (True, "127.0.0.1/32", "::1", "::1"),
    (True, "127.0.0.1/32", "fe80::1%untrusted-zone", "127.0.0.1"),
])
def test_forwarded_ip(trust, trusted, xff, expected):
    cfg = config(TRUST_PROXY_HEADERS=str(trust).lower(), TRUSTED_PROXY_CIDRS=trusted)
    assert app.client_ip(("127.0.0.1", 1234), Headers({"X-Forwarded-For": xff}), cfg) == expected


@pytest.mark.parametrize("origin,allowed,status", [
    ("https://evil.example", "", 403), ("https://app.example", "https://app.example", 101),
    ("https://evil.example", "https://app.example", 403), ("null", "", 403), ("", "", 101),
])
async def test_origin_policy(gateway_factory, origin, allowed, status):
    async with gateway_factory(config(ALLOW_ORIGIN=allowed)) as (_, url):
        if status == 101:
            async with dial(url, origin=origin):
                pass
        else:
            with pytest.raises(InvalidStatus) as error:
                async with dial(url, origin=origin):
                    pass
            assert error.value.response.status_code == status


async def test_idle_timeout_is_not_ping(gateway_factory, echo):
    port, ended = echo
    cfg = config(ALLOWED_TARGET_PORTS=str(port), IDLE_TIMEOUT_SECONDS="0.15")
    async with gateway_factory(cfg) as (_, url):
        async with dial(url) as ws:
            await target(ws, port=port)
            for _ in range(5):
                await ws.send(b"keep-data-active")
                assert await ws.recv() == b"keep-data-active"
                await asyncio.sleep(0.04)
            # Transport control frames don't reset application idle time.
            pong = await ws.ping()
            await pong
            await asyncio.wait_for(ws.wait_closed(), 2)
            assert ws.close_reason == "idle_timeout"
        await asyncio.wait_for(ended.wait(), 2)


async def test_backpressure_blocks_next_read_and_cleans_tasks():
    drain_started, drain_release = asyncio.Event(), asyncio.Event()
    send_started, send_release = asyncio.Event(), asyncio.Event()
    ws_reads, tcp_reads = [], []

    class Ws:
        def __aiter__(self):
            return self
        async def __anext__(self):
            ws_reads.append(1)
            return b"phone"
        async def send(self, data):
            send_started.set()
            await send_release.wait()
    class Reader:
        async def read(self, count):
            tcp_reads.append(1)
            return b"target"
    class Writer:
        def write(self, data):
            assert data == b"phone"
        async def drain(self):
            drain_started.set()
            await drain_release.wait()

    task = asyncio.create_task(app.relay(Ws(), Reader(), Writer(), 10, [0, 0]))
    await asyncio.wait_for(drain_started.wait(), 2)
    await asyncio.wait_for(send_started.wait(), 2)
    await asyncio.sleep(0)
    assert len(ws_reads) == len(tcp_reads) == 1
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert not [t for t in asyncio.all_tasks() if t.get_name().startswith("gateway:")]


async def test_server_shutdown_closes_tcp(gateway_factory, echo):
    port, ended = echo
    async with gateway_factory(config(ALLOWED_TARGET_PORTS=str(port))) as (_, url):
        ws = await dial(url)
        assert (await target(ws, port=port))["ok"] is True
    await asyncio.wait_for(ended.wait(), 2)
    assert ws.close_code == 1001


async def test_cancellation_during_tcp_cleanup_is_awaited(monkeypatch, caplog):
    closing, release = asyncio.Event(), asyncio.Event()

    class Writer:
        def close(self):
            closing.set()
        async def wait_closed(self):
            await release.wait()
    class Ws:
        async def recv_streaming(self):
            yield '{"version":1,"host":"127.0.0.1","port":22}'
        async def send(self, data):
            pass
        async def close(self, *args):
            pass
    async def connect(*args):
        return None, Writer()
    async def eof(*args):
        pass

    monkeypatch.setattr(app.asyncio, "open_connection", connect)
    monkeypatch.setattr(app, "relay", eof)
    with caplog.at_level(logging.INFO, logger=app.LOG.name):
        session = asyncio.create_task(app.Gateway(config()).session(Ws(), "127.0.0.1"))
        await asyncio.wait_for(closing.wait(), 2)
        session.cancel()
        await asyncio.sleep(0)
        assert not session.done()
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await session
    assert "connection closed" in caplog.text
    assert not [t for t in asyncio.all_tasks() if t.get_name().startswith("gateway:")]


async def test_ipv6_tcp_connection(gateway_factory):
    finished = asyncio.Event()
    async def handle(reader, writer):
        try:
            writer.write(b"ipv6-target")
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()
            finished.set()
    async with await asyncio.start_server(handle, "::1", 0) as server:
        port = server.sockets[0].getsockname()[1]
        async with gateway_factory(config(ALLOWED_TARGET_PORTS=str(port))) as (_, url):
            async with dial(url) as ws:
                assert (await target(ws, "::1", port))["ok"] is True
                assert await ws.recv() == b"ipv6-target"
        await asyncio.wait_for(finished.wait(), 2)
