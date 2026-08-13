"""Apply database migrations, safely, at deploy time.

Run as a one-shot job *before* the application starts -- not from inside the
application's own startup. Two reasons:

*Concurrency.* Every replica running `alembic upgrade head` at boot means N
processes racing to apply the same DDL. Alembic takes no lock of its own, so
the losers fail in ways that depend on what the migration was doing. This
script takes a PostgreSQL advisory lock first, so if it is ever run
concurrently anyway, the second caller waits and then finds there is nothing
left to do.

*Failure semantics.* A migration that fails must stop the deployment, loudly,
with the old version still serving. Folded into application startup it instead
produces a replica that crash-loops while the orchestrator reports a rollout in
progress.

It also waits for the database to accept connections, because a container
scheduled alongside PostgreSQL will usually win the race to start.
"""

from __future__ import annotations

import sys
import time

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, text
from sqlalchemy.exc import SQLAlchemyError

from app.core.config import settings
from app.core.logging import configure_logging, get_logger

logger = get_logger("migrate")

# Any constant works as long as every deployment uses the same one; this is
# "soc-analyst migrations" as an arbitrary 64-bit key.
MIGRATION_LOCK_ID = 8_233_907_115_442_001

CONNECT_TIMEOUT_SECONDS = 60
RETRY_INTERVAL_SECONDS = 2


def wait_for_database(url: str, timeout: int = CONNECT_TIMEOUT_SECONDS) -> None:
    """Block until PostgreSQL accepts a connection, or give up and fail."""
    engine = create_engine(url, pool_pre_ping=True)
    deadline = time.monotonic() + timeout
    attempt = 0

    while True:
        attempt += 1
        try:
            with engine.connect() as connection:
                connection.execute(text("SELECT 1"))
            logger.info("database is accepting connections")
            engine.dispose()
            return
        except SQLAlchemyError as exc:
            if time.monotonic() >= deadline:
                engine.dispose()
                raise RuntimeError(
                    f"database was not reachable within {timeout}s: {exc}"
                ) from exc
            logger.info("waiting for the database (attempt %d)", attempt)
            time.sleep(RETRY_INTERVAL_SECONDS)


def ensure_extensions(url: str) -> None:
    """Create the extensions the schema depends on.

    The compose file seeds these through the image's init directory, but that
    only runs on a *first* cluster start. A managed database -- RDS, Cloud SQL,
    Neon -- never runs it at all, so the migration job creates them itself. All
    three are IF NOT EXISTS, so running this against a prepared cluster is a
    no-op.
    """
    engine = create_engine(url)
    try:
        with engine.begin() as connection:
            for extension in ("vector", "pg_trgm"):
                connection.execute(text(f'CREATE EXTENSION IF NOT EXISTS "{extension}"'))
        logger.info("required extensions are present")
    except SQLAlchemyError as exc:
        # A restricted role may not be allowed to create extensions. That is
        # fine if an administrator has already done it; the migration will fail
        # clearly enough if they have not.
        logger.warning(
            "could not ensure extensions (%s); assuming they are already installed", exc
        )
    finally:
        engine.dispose()


def run_migrations() -> None:
    """Upgrade to head under an advisory lock."""
    url = settings.sync_database_url
    engine = create_engine(url)

    with engine.connect() as connection:
        logger.info("acquiring the migration lock")
        # Blocks rather than failing: a concurrent deploy should queue, not
        # abort. The lock is released when this connection closes.
        connection.execute(text("SELECT pg_advisory_lock(:key)"), {"key": MIGRATION_LOCK_ID})
        connection.commit()

        try:
            config = Config("alembic.ini")
            config.set_main_option("sqlalchemy.url", url)
            logger.info("applying migrations")
            command.upgrade(config, "head")
            logger.info("migrations are up to date")
        finally:
            connection.execute(
                text("SELECT pg_advisory_unlock(:key)"), {"key": MIGRATION_LOCK_ID}
            )
            connection.commit()

    engine.dispose()


def main() -> int:
    configure_logging()
    try:
        wait_for_database(settings.sync_database_url)
        ensure_extensions(settings.sync_database_url)
        run_migrations()
    except (RuntimeError, SQLAlchemyError):
        # Non-zero stops the deployment with the previous version still up.
        logger.exception("migration failed")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
