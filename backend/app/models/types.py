"""Custom column types."""

from __future__ import annotations

from typing import Any

from sqlalchemy import Dialect
from sqlalchemy.dialects.postgresql import INET
from sqlalchemy.types import TypeDecorator


class INETStr(TypeDecorator[str]):
    """A PostgreSQL INET column that reads back as a string.

    The drivers disagree: asyncpg returns ``ipaddress.IPv4Address`` while psycopg
    returns ``str``. Left alone, the Python type of a loaded row would depend on
    which driver loaded it, and would not match the ``Mapped[str]`` annotation.
    Normalising on the way out makes the two behave alike.

    Storage is unchanged -- still INET, so PostgreSQL still validates the value
    and the address operators still apply.
    """

    impl = INET
    cache_ok = True

    def process_result_value(self, value: Any, dialect: Dialect) -> str | None:
        return None if value is None else str(value)
