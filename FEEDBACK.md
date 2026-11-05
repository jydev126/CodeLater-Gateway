# CodeLater feedback receiver (v1)

This optional service is independent of `app.py` and the authenticated WSS tunnel. It accepts anonymous problem reports and suggestions, stores them locally, and sends no outbound messages. It has no access to the Gateway password or target network. The existing Gateway image, dependencies and Compose service do not change.

## Deployment

The client must use HTTPS. Terminate TLS at the existing NAS/reverse proxy and expose exactly `/v1/feedback`. Run this service on the private proxy network or host loopback only. Do not expose port 8766 directly to the Internet. There is no authentication secret in the APK.

```sh
docker compose -f docker-compose.feedback.yml up -d --build
```

This creates a separate non-root container and persistent named volume. The database and its WAL/SHM belong to UID/GID 10001; application-created files are private. Do not mount a read-only directory over `/data`. Back up the SQLite database with SQLite's backup API, or stop the service before copying the database together with any WAL/SHM. Do not delete the named volume during an upgrade. Docker deployment has not been validated by the coding agent.

Add the following location to the already configured TLS virtual host (including its existing custom HTTPS port, if any). Keep the Gateway's `/v1/tunnel` location unchanged:

```nginx
# http context, once:
limit_req_zone $binary_remote_addr zone=feedback:1m rate=5r/m;

# Inside the existing TLS server:
location = /v1/feedback {
    client_max_body_size 64k;
    client_body_timeout 10s;
    limit_req zone=feedback burst=5 nodelay;
    limit_req_status 429;
    proxy_pass http://127.0.0.1:8766;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header Connection "";
    proxy_connect_timeout 3s;
    proxy_read_timeout 15s;
    proxy_send_timeout 15s;
    proxy_buffering off;
    access_log off;
}
```

If the proxy is itself in Docker, connect it to `feedback-proxy` and use `http://feedback:8766`. Do not attach the feedback service to the Gateway's target/LAN network. Set `FEEDBACK_TRUSTED_PROXIES` to the exact socket peers of your controlled proxy (comma-separated CIDRs). Never trust public or unrelated container subnets. The proxy must overwrite `X-Real-IP`; the receiver ignores it from untrusted peers. Without this setting, proxied clients share a source quota. No CORS/Origin is accepted; this endpoint is for the native app.

For a local process, install `requirements-feedback.txt` into a separate environment and set `FEEDBACK_DATABASE` to an absolute path before `python feedback.py`. Defaults: loopback port 8766, 5 new reports/source/hour, 100 total/hour, 10,000 retained records, 64 MiB of payloads. Override with `FEEDBACK_PER_IP_HOUR`, `FEEDBACK_GLOBAL_HOUR`, `FEEDBACK_MAX_RECORDS`, `FEEDBACK_MAX_BYTES`. Reaching capacity returns 503 without falsely confirming receipt. Monitor disk/volume capacity separately: SQLite indexes and journaling require extra space. No automatic content deletion is enabled.

## Protocol

`POST /v1/feedback`, `Content-Type: application/json`, UTF-8, at most 64 KiB, no compression. `Idempotency-Key` must exactly match the lowercase UUIDv4 body `id`. Unknown fields, duplicate JSON keys and malformed types are rejected. The receiver accepts a complete report body, never attachments.

```json
{
  "version": 1,
  "id": "9d43f72c-97ce-4b19-90f3-f72c9140e5f9",
  "kind": "bug",
  "description": "Describe the problem",
  "details": "Steps to reproduce, or the suggestion's use case",
  "contact": "",
  "metadata": {
    "appVersion": "0.9.7",
    "buildNumber": "14",
    "androidSdk": 35,
    "language": "en"
  }
}
```

`kind`: `bug` or `suggestion`. Description: 1–4000 characters (not all whitespace); details: 0–4000; contact: optional text of up to 320 characters, represented by an empty string when absent. The app must warn users not to include secrets in their own text. Metadata has exactly the four fields shown; `language` is `en` or `zh-Hans`, SDK is an integer from 24 to 100, version/build are constrained release identifiers.

Optional `diagnostics` is a separately previewed and explicitly included object with **only**:

```json
{"version":1,"databaseVersion":19,"logCounts":{"info":0,"warning":0,"error":0}}
```

Each count is an integer 0–1000. No log messages, host/project names, paths, commands, source, conversation contents, raw exceptions, headers, tokens, passwords or keys are valid diagnostic fields. The server validates this whitelist independently of the app. User-entered description/contact are deliberately retained as entered; they are not claimed to be automatically scrubbed.

Receipt after durable commit: HTTP 201 and `{"version":1,"status":"received","id":"<same id>"}`. Retry with the same ID and canonically identical body returns the same receipt with HTTP 200, including after restart. A changed body under the same ID returns 409 (`id_conflict`), without exposing the original report. The client must verify both status and ID; opening a URL, timing out, receiving HTML or receiving an unrelated 200 is not a receipt.

Other responses: 400 `invalid_request`; 408 `request_timeout`; 413 `too_large`; 415 `unsupported_media`; 429 `rate_limited` (Retry-After); 503 `busy`, `storage_full` or `unavailable`. No automatic retry/submission is required. Keep the offline draft and pending envelope until the user retries or the matching receipt is saved. Reports are idempotent but intentionally edited payloads require a new UUID.

## Operator access and privacy

`GET /healthz` reports the service name/version only. There is **no public list/read/delete endpoint** and no webhook/GitHub token. An operator with local filesystem access reads the SQLite `feedback` table (`id`, `payload`, `received_at`) using a local SQLite client. This is the inbox; forwarding issues or contacting the optional address is an operator action, not something this service does automatically. Received payloads may contain personal data supplied by the sender; restrict operator access and define a retention policy for the actual deployment before collecting production reports.

The service does not persist source IPs or request headers. Rate quotas store HMAC source buckets (salt stays in the database), expire after the current hour, and survive process restart. A bounded in-memory attempt limiter also limits malformed requests. Access/body logging is disabled; storage errors return fixed codes without paths or raw exceptions. Keep reverse-proxy request-body/header logging disabled as well.

## Validation and rollout gate

```sh
uv venv .venv-feedback
uv pip install --python .venv-feedback/bin/python -r requirements-feedback.txt -r requirements-dev.txt
.venv-feedback/bin/python -m pytest tests/test_feedback.py tests/test_gateway.py
```

The checked-in integration tests run real loopback HTTP plus SQLite and cover duplicate/concurrent/restart receipts, conflicting IDs, rate limits/proxy trust, body limits, whitelist injections, storage failure, timeouts and absence of public read access. They do not prove the production TLS reverse proxy is deployed. Before enabling a distributed APK endpoint, configure the exact route above, check the health endpoint privately, and submit an explicitly marked synthetic report through the public HTTPS route, verifying the matching ID in the operator inbox. Record that test separately; local service success must not be reported as production delivery.
