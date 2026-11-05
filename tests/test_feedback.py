import asyncio
import dataclasses
import ipaddress
import json
import sqlite3
import uuid

import pytest
from aiohttp.test_utils import TestClient, TestServer

from feedback import Config, MAX_BODY, create_app


@pytest.fixture
def payload():
    return {"version": 1, "id": str(uuid.uuid4()), "kind": "bug",
            "description": "A test problem", "details": "Open the app", "contact": "",
            "metadata": {"appVersion": "0.9.7", "buildNumber": "14", "androidSdk": 35, "language": "en"}}


@pytest.fixture
def config(tmp_path):
    return Config(tmp_path / "feedback.db")


async def client(config, **kwargs):
    result = TestClient(TestServer(create_app(config, **kwargs)))
    await result.start_server()
    return result


async def submit(client, payload, **kwargs):
    return await client.post("/v1/feedback", json=payload, headers={"Idempotency-Key": payload["id"], **kwargs})


def records(config):
    with sqlite3.connect(config.database) as db:
        return db.execute("SELECT payload FROM feedback").fetchall()


@pytest.mark.asyncio
async def test_success_is_persisted_before_receipt_and_duplicate_survives_restart(config, payload):
    async with await client(config) as api:
        response = await submit(api, payload)
        assert response.status == 201
        assert await response.json() == {"version": 1, "status": "received", "id": payload["id"]}
        assert json.loads(records(config)[0][0]) == payload
    async with await client(config) as api:
        response = await submit(api, payload)
        assert response.status == 200
        assert len(records(config)) == 1
    assert config.database.stat().st_mode & 0o077 == 0


@pytest.mark.asyncio
async def test_concurrent_idempotency_and_changed_body_conflict(config, payload):
    async with await client(config) as api:
        responses = await asyncio.gather(*(submit(api, payload) for _ in range(6)))
        assert sorted(r.status for r in responses) == [200]*5 + [201]
        changed = {**payload, "description": "edited"}
        response = await submit(api, changed)
        assert response.status == 409
        assert "id" not in await response.json()
        assert json.loads(records(config)[0][0])["description"] == payload["description"]


@pytest.mark.asyncio
async def test_per_source_rate_persists_and_duplicate_does_not_consume_quota(config, payload):
    config = dataclasses.replace(config, per_ip_hour=1)
    async with await client(config, now=lambda: 3601) as api:
        assert (await submit(api, payload)).status == 201
    async with await client(config, now=lambda: 3602) as api:
        assert (await submit(api, payload)).status == 200
        other = {**payload, "id": str(uuid.uuid4())}
        response = await submit(api, other, **{"X-Real-IP": "203.0.113.9"})
        assert response.status == 429  # untrusted header cannot evade the limit
        assert response.headers["Retry-After"] == "3600"
    async with await client(config, now=lambda: 7201) as api:
        assert (await submit(api, other)).status == 201
    assert b"127.0.0.1" not in config.database.read_bytes()


@pytest.mark.asyncio
async def test_trusted_proxy_header_and_global_rate(config, payload):
    config = dataclasses.replace(config, per_ip_hour=1, global_hour=2,
                                 trusted_proxies=(ipaddress.ip_network("127.0.0.1/32"),))
    async with await client(config) as api:
        for index, expected in enumerate((201, 201, 429)):
            body = {**payload, "id": str(uuid.uuid4())}
            response = await submit(api, body, **{"X-Real-IP": f"203.0.113.{index+1}"})
            assert response.status == expected


@pytest.mark.parametrize("field,value", [
    ("rawLog", "Authorization: secret"), ("token", "private-token"),
    ("path", "/home/private/code"), ("privateKey", "-----BEGIN PRIVATE KEY-----"),
    ("command", "ssh private-host"), ("conversation", "private reply"),
])
@pytest.mark.asyncio
async def test_diagnostics_reject_any_non_whitelisted_field(config, payload, field, value):
    payload["diagnostics"] = {"version": 1, "databaseVersion": 19,
                              "logCounts": {"info": 1, "warning": 2, "error": 3}, field: value}
    async with await client(config) as api:
        response = await submit(api, payload)
        assert response.status == 400
        assert value not in await response.text()
        assert records(config) == []


@pytest.mark.asyncio
async def test_valid_diagnostics_and_suggestion_are_accepted(config, payload):
    payload["kind"] = "suggestion"
    payload["metadata"]["language"] = "zh-Hans"
    payload["diagnostics"] = {"version": 1, "databaseVersion": 19,
                              "logCounts": {"info": 1, "warning": 2, "error": 3}}
    async with await client(config) as api:
        assert (await submit(api, payload)).status == 201
        assert json.loads(records(config)[0][0]) == payload


@pytest.mark.parametrize("change", [
    {"version": True}, {"id": "not-a-uuid"}, {"kind": "log"},
    {"description": " "}, {"description": "x"*4001}, {"contact": "x"*321},
    {"headers": {"Authorization": "secret"}},
    {"metadata": {"appVersion": "0.9.7", "buildNumber": "14", "androidSdk": True, "language": "en"}},
    {"metadata": {"appVersion": "/private/path", "buildNumber": "14", "androidSdk": 35, "language": "en"}},
])
@pytest.mark.asyncio
async def test_invalid_schema_does_not_persist_or_echo(config, payload, change):
    payload.update(change)
    async with await client(config) as api:
        response = await submit(api, payload)
        assert response.status == 400
        assert await response.json() == {"version": 1, "status": "invalid_request"}
        assert records(config) == []


@pytest.mark.asyncio
async def test_rejects_missing_idempotency_duplicate_json_keys_and_oversized_input(config, payload):
    async with await client(config) as api:
        assert (await api.post("/v1/feedback", json=payload)).status == 400
        duplicate = '{"id":"first","id":"second"}'
        assert (await api.post("/v1/feedback", data=duplicate, headers={"Content-Type": "application/json"})).status == 400
        assert (await api.post("/v1/feedback", data=b"x"*(MAX_BODY+1), headers={"Content-Type": "application/json"})).status == 413
        assert (await submit(api, payload, **{"Content-Encoding": "gzip"})).status == 415
        assert (await submit(api, payload, Origin="https://untrusted.invalid")).status == 400
        assert records(config) == []


@pytest.mark.asyncio
async def test_storage_failure_and_capacity_never_acknowledge_success(config, payload):
    class BrokenStore:
        def submit(self, *args):
            raise sqlite3.OperationalError("private-path private-token")
    async with await client(config, store=BrokenStore()) as api:
        response = await submit(api, payload)
        assert response.status == 503
        assert "private" not in await response.text()
    config = dataclasses.replace(config, max_bytes=10)
    async with await client(config) as api:
        assert (await submit(api, payload)).status == 503
        assert records(config) == []


@pytest.mark.asyncio
async def test_read_timeout_releases_inflight_capacity(config, payload):
    config = dataclasses.replace(config, read_timeout=0.03, max_inflight=1)
    async def slow_body():
        yield b'{'
        await asyncio.sleep(0.2)
    async with await client(config) as api:
        response = await api.post("/v1/feedback", data=slow_body(), headers={"Content-Type":"application/json"})
        assert response.status == 408
        assert (await submit(api, payload)).status == 201


@pytest.mark.asyncio
async def test_no_public_read_list_or_cross_service_tunnel_route(config, payload):
    async with await client(config) as api:
        assert (await submit(api, payload)).status == 201
        assert (await api.get("/v1/feedback")).status == 405
        assert (await api.get("/v1/feedback/" + payload["id"])).status == 404
        assert (await api.get("/v1/tunnel")).status == 404
        health = await (await api.get("/healthz")).json()
        assert health == {"service":"codelater-feedback", "version":1}
