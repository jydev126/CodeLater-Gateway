"""Optional real CodeLater transport check; stdlib runner, outside default pytest.

Usage: .venv/bin/python tests/client_smoke.py /path/to/dart ../CodeLater
Requires CodeLater's existing .dart_tool/package_config.json; does not fetch packages.
"""

import asyncio
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app import Config, Gateway  # noqa: E402


async def main():
    dart, client_root = sys.argv[1:]
    tasks = set()

    async def echo(reader, writer):
        task = asyncio.current_task()
        tasks.add(task)
        try:
            while data := await reader.read(65536):
                writer.write(data)
                await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()
            tasks.remove(task)

    async with await asyncio.start_server(echo, "127.0.0.1", 0) as tcp:
        port = tcp.sockets[0].getsockname()[1]
        cfg = Config.from_env({
            "GATEWAY_PASSWORD": "test-only:随机-password-123456",
            "ALLOWED_TARGET_CIDRS": "127.0.0.1/32",
            "ALLOWED_TARGET_PORTS": str(port),
        })
        gateway = Gateway(cfg)
        async with gateway.server(host="127.0.0.1", port=0) as server:
            ws_port = server.sockets[0].getsockname()[1]
            process = await asyncio.create_subprocess_exec(
                dart, f"--packages={Path(client_root).resolve() / '.dart_tool/package_config.json'}",
                str(Path(__file__).with_name("codelater_client_smoke.dart")),
                f"ws://127.0.0.1:{ws_port}", str(port))
            try:
                result = await asyncio.wait_for(process.wait(), 45)
            finally:
                if process.returncode is None:
                    process.kill()
                    await process.wait()
        if tasks:
            await asyncio.wait_for(asyncio.gather(*tasks), 5)
        assert gateway.active == 0
        assert not [t for t in asyncio.all_tasks() if t.get_name().startswith("gateway:")]
        if result:
            raise SystemExit(result)


if __name__ == "__main__":
    asyncio.run(main())
