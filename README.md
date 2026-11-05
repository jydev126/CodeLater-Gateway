# CodeLater Gateway

`codelater-gateway` 只是 **generic authenticated WSS-to-TCP relay**：经过简单认证和限制的字节隧道。它不是 CodeLater backend，不知道 SSH、Code、Git、Codex 或 ZeroTier；没有设备、工作区、文件 API、数据库或持久 session。

```text
CodeLater → WSS :443 → NAS Reverse Proxy（TLS 终止）
                         → ws/http :8765 → Gateway Docker → 普通 TCP → target IP:port
```

Gateway 仅调用 `asyncio.open_connection(host, port)`。网络可达性由 Docker / NAS / Router / 用户网络配置负责。服务不安装、调用或管理 ZeroTier，不改路由、iptables 或网络。**禁止使用 `network_mode: host`。**

## 可选反馈接收端

独立的匿名 HTTPS 反馈服务见 [FEEDBACK.md](FEEDBACK.md)。它使用自己的进程、依赖、数据库和 Docker 网络，不改变本页 WSS 隧道服务。

## 快速部署

1. 在 NAS 预先准备可达目标的 external Docker network，默认名称 `lan`。它可以是 bridge、ipvlan、macvlan 或 NAS 提供的网络；本项目不创建它，也不假设具体子网。
2. 复制 `.env.example` 为 `.env`，修改 `GATEWAY_PASSWORD`（至少 20 个随机字符）和目标 CIDR / 端口白名单。示例密码 `CHANGE_ME` 会导致启动失败；没有内置默认密码。建议将 `.env` 权限设为 `600`，不要提交或共享它。
3. **启动 Gateway 前先验证容器网络能普通 TCP connect 到目标**。可先构建镜像，再使用下方一次性容器命令，或用已有接入同一网络的 Python 容器验证。
4. 启动服务并配置 NAS TLS 反向代理。公网客户端只使用 WSS，Python 服务内部没有 TLS。

```bash
cp .env.example .env
chmod 600 .env
# 编辑 .env 后：
docker compose build
# 替换示例地址及端口；run 会使用 compose 中的两个网络。
docker compose run --rm --no-deps gateway python -c "import socket; s=socket.create_connection(('10.147.20.31',22),5); print(s.recv(100)); s.close()"
docker compose up -d
```

网络验证预期看到类似 `SSH-2.0-OpenSSH...`；这是部署人员读取 TCP 字节验证连通性，不是 Gateway 理解 SSH。若失败，先修复 Docker/NAS 网络；修改 Gateway 应用代码不能解决容器路由问题。若目标网络由 NAS 或底层 ZeroTier 承担，仍需保证该容器网络能到达目标。

Compose 显式使用两个网络：`proxy` bridge 用于代理入口，`lan` 为用户预先创建的 external network，名称由 `CODELATER_LAN_NETWORK` 指定。只向 NAS 回环发布 `127.0.0.1:8765:8765`；不要把 8765 直接开放到公网。更改容器监听端口时，同时修改端口映射和代理配置。

Dockerfile 基于 Python 3.12 slim，固定非 root UID/GID 10001，仅安装一个运行依赖 `websockets`。Compose 使用只读文件系统、移除 capabilities，SIGTERM 会关闭活动隧道。Python 3.12+ 均可运行。

Docker 构建中的 PyPI 索引也默认清华镜像，可用 build arg `PIP_INDEX_URL` 调整。WebSocket API 采用 [websockets 官方 asyncio server 接口](https://websockets.readthedocs.io/en/16.0/reference/asyncio/server.html)。

## NAS / Nginx 反向代理

已有 NAS HTTPS 虚拟主机 `code.example.com` 负责证书和 443 端口。在该 TLS server 中加入：

```nginx
location = /v1/tunnel {
    proxy_pass http://127.0.0.1:8765;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
    proxy_set_header Authorization $http_authorization;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_read_timeout 3600s;
    proxy_send_timeout 3600s;
    proxy_buffering off;
}
```

公网地址为 `wss://code.example.com/v1/tunnel`，内部为 `ws://127.0.0.1:8765/v1/tunnel`。通用 NAS 代理需开启 WebSocket / HTTP 1.1 Upgrade，保留 Authorization、Origin 和 Sec-WebSocket-Protocol，禁止响应缓冲，设置足够长的读写超时。不要记录 Authorization 或 payload，不要剥离 Origin。

若 NAS 反向代理本身在 Docker，将其接入此项目的 `proxy` 网络（Compose 默认实际名为 `<project>_proxy`，请按部署项目名配置），上游使用 `http://gateway:8765`。代理和 Gateway 共享该网络即可，不需要 host network。可通过代理自身的 Compose external network 引用这个已创建网络。

CodeLater 允许基址带路径前缀，例如 `https://code.example.com/codelater`，实际请求为 `/codelater/v1/tunnel`。Gateway 仍只接受 `/v1/tunnel`；需要在代理中使用精确位置和重写后的上游 URI：

```nginx
location = /codelater/v1/tunnel {
    proxy_pass http://127.0.0.1:8765/v1/tunnel;
    # 其余 proxy_* 指令与上例相同，实际部署时复制到此处。
}
```

默认不信任 `X-Forwarded-For`，代理后的客户端共享同一个来源计数。只有设置 `TRUST_PROXY_HEADERS=true` 且真实 socket peer 属于 `TRUSTED_PROXY_CIDRS` 时才读取转发链。链从右向左剥离可信代理，取最近的不可信节点，避免客户端伪造左侧地址；非法、重复或过长的 header 回退到 socket peer。仅填写受控代理的精确 IP/CIDR（例如 `172.18.0.2/32`），不要把不受控容器、互联网或目标网络一并设为可信。

## 配置

服务启动读取环境变量；直接 `python app.py` 不自动加载 `.env`。Docker Compose 通过 `env_file` 注入。没有 CIDR 默认放行；配置非法会明确报错并退出，错误中不输出值或密码。

| 变量 | 默认 / 要求 |
| --- | --- |
| `GATEWAY_PASSWORD` | 必填，无默认，不能空白或 `CHANGE_ME`，推荐 20+ 随机字符 |
| `GATEWAY_PASSWORD_FILE` | 可选；配置后始终优先，文件不可读/内容无效就启动失败；去掉文件尾部 CR/LF，保留其他字符 |
| `LISTEN_HOST` / `LISTEN_PORT` | `0.0.0.0` / `8765` |
| `ALLOWED_TARGET_CIDRS` | 必须显式设置，逗号分隔的 IPv4/IPv6 CIDR |
| `ALLOWED_TARGET_PORTS` | `22`；如 `22,2222`，范围 1–65535 |
| `CONNECT_TIMEOUT_SECONDS` | `5` |
| `TARGET_HANDSHAKE_TIMEOUT_SECONDS` | `5` |
| `MAX_CONNECTIONS` / `MAX_CONNECTIONS_PER_IP` | `8` / `4`；包含等待目标握手和 TCP connect 的连接 |
| `AUTH_FAIL_LIMIT` | `5` |
| `AUTH_FAIL_WINDOW_SECONDS` / `AUTH_BLOCK_SECONDS` | `300` / `900` |
| `IDLE_TIMEOUT_SECONDS` | `1800`；双向成功转发非空应用字节才刷新，Ping/Pong 不刷新 |
| `TRUST_PROXY_HEADERS` | `false` |
| `TRUSTED_PROXY_CIDRS` | 空；开启代理信任时必须配置 |
| `ALLOW_ORIGIN` | 空；非空 Origin 默认拒绝；可指定一个精确 Origin，不支持 `*` |
| `CODELATER_LAN_NETWORK` | `lan`；仅供 Compose 使用 |

所有超时和连接/认证计数必须为正数。IPv4/IPv6 target 必须是 literal，不接受域名、IPv6 zone ID；端口和版本必须是 JSON 整数（不接受 bool/float）。白名单同时核对 CIDR 与端口。请尽可能缩小范围，**不要配置 `0.0.0.0/0` 或 `::/0` 将其变成公开 TCP proxy**；示例中的 `10.0.0.0/8` 也应替换成实际最小范围。

密码可含冒号和 UTF-8 字符，与 CodeLater 的 Basic 编码一致。`.env` 中含 `$`、`#` 等字符时使用单引号，避免 Compose 插值改变密码。

认证失败的前 5 次返回 401；达到阈值后的请求在封禁期内返回 429（即使随后密码正确）。成功认证不会清除仍有效的失败记录。计数只在本进程内保存，重启清空；最多保存 10,000 个未过期来源，达到上限时新来源临时返回 429，旧来源仍按原规则处理。单实例个人使用设计，不做跨实例共享。

### Docker Secret

也可在自己的 Compose override 中增加文件型 secret，并在 `.env` 设置 `GATEWAY_PASSWORD_FILE=/run/secrets/gateway_password`：

```yaml
services:
  gateway:
    secrets:
      - gateway_password
secrets:
  gateway_password:
    file: ./secrets/gateway_password
```

由部署人员准备 secret 文件，确保容器 UID 10001 可读。普通 Compose 文件型 secret 依赖宿主文件权限，不保证通过 `uid/gid/mode` 重映射权限；按 NAS 实际挂载方式设置。Gateway 只读取，不创建或写入密码文件。`.env` 和 `secrets/` 已被 Git 忽略，Docker build context 只允许应用、requirements 和 Dockerfile。

## 与 CodeLater 的协议

固定 `GET /v1/tunnel` 和 `codelater-tunnel-v1` 子协议；其他路径返回 404（仅 `/healthz` 例外）。握手前验证 `Authorization: Basic base64(UTF8("codelater:<password>"))`，密码用 `secrets.compare_digest` 比较。认证失败 HTTP 401，认证限流 HTTP 429，Origin 拒绝 HTTP 403，缺少/错误子协议 HTTP 400。

升级后的第一条消息是最多 2048 UTF-8 字节的 Text JSON，分片累计同样受限，必须在握手超时内完整到达：

```json
{"version":1,"host":"10.147.20.31","port":22}
```

允许的目标进行一次普通 TCP connect，不 retry、probe 或 DNS。连接成功返回 `{"version":1,"ok":true}`，随后仅双向 Binary。建立前错误为 `{"version":1,"ok":false,"code":"target_unreachable"}`，固定 code 为 `bad_request`、`target_denied`、`target_unreachable`、`busy`、`internal_error`。并发满额在升级后返回 `busy` 并以 1013 关闭，与 CodeLater 现有错误映射兼容。

Raw relay 中 Text 导致 1002 / `protocol_error`；消息超过 1 MiB 导致 1009；应用 idle 导致 1001 / `idle_timeout`。传输限制超大 initial message 时也可能直接触发 1009。成功握手后不再插入 JSON 错误。保持字节顺序，不保持 TCP/WS 消息边界。关闭任一方向会取消另一方向并释放 TCP、WebSocket 和所有 relay task；不支持 TCP half-close。

无压缩，Ping 间隔 25 秒 / 超时 20 秒，WS 接收队列最多 4 个 frame，最大消息 1 MiB，TCP 读取块 64 KiB。两侧分别直接 `await writer.drain()` / `await websocket.send()` 传递 backpressure，无应用层无界队列。日志只含时间、来源、已允许的目标、连接状态、时长、字节计数和固定错误分类；禁用库原始握手/payload 日志，不记录密码、Authorization、SSH 内容、异常 repr 或 traceback。

## 功能测试

使用本地 TCP echo / 模拟阻塞和失败场景；pytest 不依赖 Docker、互联网、SSH server 或 ZeroTier。

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -i https://pypi.tuna.tsinghua.edu.cn/simple -r requirements-dev.txt
.venv/bin/python -m pytest
```

依赖下载默认使用大陆镜像。运行时只需要 `requirements.txt`；pytest 依赖单独保存在 `requirements-dev.txt`。按本次要求不执行 Docker 测试；NAS TLS、Docker 网络、手机实机需按下节部署后验收。

可选的真实 CodeLater transport 互通测试：已有相邻 CodeLater checkout、其 Dart package 配置和 Dart SDK 后运行以下命令。它启动本地 Python Gateway 与 TCP echo，直接调用 CodeLater 的 `WebSocketSshSocket`，验证 2 MiB+ 字节流、关闭、401 和 target_denied 映射，不下载额外 Dart 包。

```bash
.venv/bin/python tests/client_smoke.py /path/to/dart ../CodeLater
```

## 部署后手工 E2E

1. 完成前述容器网络预检后，`docker compose up -d`。
2. NAS 本机请求 `http://127.0.0.1:8765/healthz`，预期 `200` / `ok`；也可在容器中运行：
   ```bash
   docker compose exec gateway python -c "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8765/healthz',timeout=3).read().decode())"
   ```
   Health 只表示进程正常，不探测 target 或外网。
3. 用同一个普通 Python socket 命令再次核对运行中容器对目标的 TCP 连通性：
   ```bash
   docker compose exec gateway python -c "import socket; s=socket.create_connection(('10.147.20.31',22),5); print(s.recv(100)); s.close()"
   ```
4. 配置 NAS 反向代理及有效的 TLS 证书，公网仅开放 HTTPS/WSS 443。
5. 手机 CodeLater 填写 Gateway 基址 `https://code.example.com`（不含 `/v1/tunnel`）、Gateway Password 和目标 `10.147.20.31:22`。目标必须位于白名单内。
6. 在 CodeLater 核对目标 SSH host key，再验证 SSH 密码/私钥认证、SFTP、exec；这些功能由手机和目标端负责。切换 Wi-Fi/移动网络并断开重连，核对错误密码、不可达目标和目标拒绝的提示。

项目记忆统一维护在相邻 CodeLater 项目的 `memory/gateway-transport.md` 与 `memory/post-m5.md`，这里不单独创建 memory。
