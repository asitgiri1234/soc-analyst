"""Every runtime import must be installable from requirements.txt.

This exists because it went wrong: `httpx` was imported by the Groq provider
and the HTTP embedding provider but declared only as a *dev* dependency. Tests
passed, because the test environment installs the dev set -- and a production
image, built from requirements.txt alone, would have failed at import time and
never served a request.

A test that only exercises the code cannot catch that. This one reads what the
application imports and checks it against what the deployment installs.
"""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parent.parent
APP_ROOT = BACKEND_ROOT / "app"
REQUIREMENTS = BACKEND_ROOT / "requirements.txt"

# Distribution name -> the module name it provides, where they differ.
DISTRIBUTION_MODULES = {
    "sqlalchemy[asyncio]": "sqlalchemy",
    "psycopg[binary]": "psycopg",
    "uvicorn[standard]": "uvicorn",
    "pyjwt": "jwt",
    "argon2-cffi": "argon2",
    "python-multipart": "multipart",
    "pydantic-settings": "pydantic_settings",
    "email-validator": "email_validator",
}


def declared_modules() -> set[str]:
    """The top-level modules requirements.txt makes available."""
    modules: set[str] = set()

    for line in REQUIREMENTS.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        # Strip the version specifier: `fastapi>=0.115` -> `fastapi`.
        name = re.split(r"[<>=!~;\s]", stripped, maxsplit=1)[0].strip().lower()
        if not name:
            continue

        modules.add(DISTRIBUTION_MODULES.get(name, name.replace("-", "_")))
        # `sqlalchemy[asyncio]` also needs matching without its extra.
        bare = name.split("[")[0]
        modules.add(DISTRIBUTION_MODULES.get(bare, bare.replace("-", "_")))

    return modules


def imported_modules() -> dict[str, set[str]]:
    """Top-level modules imported anywhere under `app/`, and by which files."""
    found: dict[str, set[str]] = {}

    for path in APP_ROOT.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                # `level > 0` is a relative import, which is always first-party.
                if node.level or node.module is None:
                    continue
                names = [node.module]
            else:
                continue

            for name in names:
                top = name.split(".")[0]
                found.setdefault(top, set()).add(str(path.relative_to(BACKEND_ROOT)))

    return found


def test_every_third_party_runtime_import_is_declared() -> None:
    declared = declared_modules()
    undeclared: dict[str, set[str]] = {}

    for module, files in imported_modules().items():
        if module == "app":  # first-party
            continue
        if module in sys.stdlib_module_names:
            continue
        if module in declared:
            continue
        undeclared[module] = files

    assert not undeclared, (
        "these modules are imported by app/ but are not in requirements.txt, so a "
        f"production image would fail at import: { {k: sorted(v) for k, v in undeclared.items()} }"
    )


def test_httpx_is_a_runtime_dependency() -> None:
    """The specific regression above, named so it cannot quietly come back."""
    assert "httpx" in declared_modules()


def test_requirements_pin_a_minimum_version() -> None:
    """An unpinned dependency resolves differently on every build."""
    unpinned = []

    for line in REQUIREMENTS.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if not re.search(r"[<>=~]", stripped):
            unpinned.append(stripped)

    assert not unpinned, f"no version constraint on: {unpinned}"
