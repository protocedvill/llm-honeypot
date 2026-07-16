"""Process entrypoint: runs the honeypot (public, port 8000) and, if
CONSOLE_TOKEN is set, the operator console (port CONSOLE_PORT) concurrently
in one process. The console is intentionally a second ASGI app on its own
port rather than a route on the honeypot app -- a pentest agent scanning the
honeypot's port should never be able to discover or reach it at all.
"""

import asyncio
import logging

import uvicorn

from app.config import get_settings

logger = logging.getLogger(__name__)


async def main() -> None:
    from app.main import app as honeypot_app

    settings = get_settings()
    servers = [
        uvicorn.Server(
            uvicorn.Config(
                honeypot_app,
                host="0.0.0.0",
                port=8000,
                log_level="info",
                server_header=False,
            )
        )
    ]

    if settings.console_token:
        from app.console.main import app as console_app

        servers.append(
            uvicorn.Server(
                uvicorn.Config(
                    console_app,
                    host="0.0.0.0",
                    port=settings.console_port,
                    log_level="info",
                    server_header=False,
                )
            )
        )
    else:
        logger.warning("CONSOLE_TOKEN not set -- operator console disabled")

    await asyncio.gather(*(server.serve() for server in servers))


if __name__ == "__main__":
    asyncio.run(main())
