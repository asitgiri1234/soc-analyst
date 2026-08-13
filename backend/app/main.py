"""FastAPI application entrypoint."""

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app import __version__
from app.api.v1.router import api_router
from app.core.config import settings
from app.core.logging import configure_logging, get_logger
from app.core.middleware import SecurityHeadersMiddleware, install_error_handlers
from app.db.redis import close_redis
from app.db.session import dispose_engine

logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncGenerator[None, None]:
    configure_logging()
    logger.info("starting %s (env=%s)", settings.PROJECT_NAME, settings.ENVIRONMENT)
    yield
    logger.info("shutting down %s", settings.PROJECT_NAME)
    await dispose_engine()
    await close_redis()


def create_app() -> FastAPI:
    # The interactive docs and the schema behind them enumerate every route,
    # parameter and error shape. That is a convenience while building and free
    # reconnaissance once deployed, so production serves neither.
    expose_docs = settings.ENVIRONMENT != "production"

    app = FastAPI(
        title=settings.PROJECT_NAME,
        version=__version__,
        # Starlette's debug mode renders the traceback -- and anything in the
        # frames, such as a database URL with its password -- into the HTTP
        # response body. It is off in every environment, including local: the
        # traceback still goes to the log, where it belongs, and dev then
        # exercises the same error path that production will.
        debug=False,
        openapi_url=f"{settings.API_V1_PREFIX}/openapi.json" if expose_docs else None,
        docs_url="/docs" if expose_docs else None,
        redoc_url="/redoc" if expose_docs else None,
        lifespan=lifespan,
    )

    # Order matters: middleware added last runs first, so the security headers
    # wrap the CORS response too.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.BACKEND_CORS_ORIGINS,
        allow_credentials=True,
        # Explicit rather than "*". With credentials allowed, a wildcard that
        # reflects whatever a caller asks for removes the point of having a
        # list of permitted origins at all.
        allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
        expose_headers=["X-Request-ID", "Retry-After"],
        max_age=600,
    )
    app.add_middleware(SecurityHeadersMiddleware)

    install_error_handlers(app)

    app.include_router(api_router, prefix=settings.API_V1_PREFIX)

    @app.get("/", tags=["system"], summary="Service banner")
    async def root() -> dict[str, str]:
        return {
            "service": settings.PROJECT_NAME,
            "version": __version__,
            "docs": "/docs",
            "api": settings.API_V1_PREFIX,
        }

    return app


app = create_app()
