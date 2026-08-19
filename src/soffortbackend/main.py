"""Process entry point loaded by Uvicorn and the project console script."""

import uvicorn

from soffortbackend.app import create_app
from soffortbackend.logging import configure_logging
from soffortbackend.settings import Settings


def build_app():  # type annotation omitted because Uvicorn imports this factory dynamically.
    """Load validated settings and construct a fresh ASGI application."""
    settings = Settings()  # type: ignore[call-arg] - required values come from the environment.
    configure_logging(settings.log_level)
    return create_app(settings)


def run() -> None:
    """Run the server with conservative proxy and disclosure defaults."""
    settings = Settings()  # type: ignore[call-arg] - required values come from the environment.
    uvicorn.run(
        "soffortbackend.main:build_app",
        factory=True,
        host=settings.bind_host,
        port=settings.port,
        access_log=False,
        server_header=False,
        proxy_headers=True,
        forwarded_allow_ips="*",  # NetworkPolicy permits only the in-cluster Gateway.
    )


if __name__ == "__main__":
    run()
