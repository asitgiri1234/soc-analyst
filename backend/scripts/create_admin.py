"""Create or promote an administrator.

Registration always produces a VIEWER, deliberately -- signing up must not be a
route to privilege. That leaves a bootstrap problem: the first administrator has
to come from somewhere outside the API.

    python -m scripts.create_admin --email you@example.com --username you

The password is read from the ADMIN_PASSWORD environment variable, or prompted
for. It is never taken from the command line, where it would end up in the shell
history and the process list.

Run against an existing account, this promotes it instead.
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import os
import sys

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.config import settings
from app.core.security import hash_password
from app.models.enums import UserRole
from app.models.user import User
from app.services.auth import get_by_email

MIN_LENGTH = settings.MIN_PASSWORD_LENGTH


def _read_password() -> str:
    password = os.environ.get("ADMIN_PASSWORD")
    if password is None:
        password = getpass.getpass("Password: ")
        if password != getpass.getpass("Confirm password: "):
            sys.exit("Passwords do not match.")
    if len(password) < MIN_LENGTH:
        sys.exit(f"Password must be at least {MIN_LENGTH} characters.")
    return password


async def _create_or_promote(session: AsyncSession, email: str, username: str) -> str:
    existing = await get_by_email(session, email)
    if existing is not None:
        if existing.role is UserRole.ADMIN and existing.is_active:
            return f"{email} is already an active administrator."
        existing.role = UserRole.ADMIN
        existing.is_active = True
        return f"Promoted {email} to administrator."

    session.add(
        User(
            email=email.lower(),
            username=username,
            hashed_password=hash_password(_read_password()),
            role=UserRole.ADMIN,
            is_active=True,
        )
    )
    return f"Created administrator {email}."


async def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--email", required=True)
    parser.add_argument("--username", required=True)
    args = parser.parse_args()

    engine = create_async_engine(settings.database_url)
    factory = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as session:
        message = await _create_or_promote(session, args.email, args.username)
        await session.commit()
    await engine.dispose()
    print(message)


if __name__ == "__main__":
    asyncio.run(main())
