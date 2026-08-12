"""The contract every LLM provider implements.

One method: given a system instruction and a user message, return the model's
text. Everything provider-specific -- authentication, retries, the response
envelope -- stays inside the implementation, so replacing Groq later is a
configuration change rather than a rewrite of the analyzer.

The analyzer never sees an API key, a URL, or an HTTP status. It sees text or
an ``LLMError``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable


class LLMError(Exception):
    """The model could not be reached or did not answer usefully.

    One exception rather than a hierarchy of transport faults: to the caller a
    timeout, a rate limit and a malformed body all mean the same thing -- no
    analysis this time.
    """


class LLMConfigurationError(LLMError):
    """The provider cannot run as configured, e.g. no API key.

    Separate because it is not transient: retrying will not supply a key, and
    the API should say so rather than reporting a temporary outage.
    """


class LLMResponseError(LLMError):
    """The model answered, but not with something usable.

    Raised when the response is not valid JSON or does not satisfy the schema.
    Kept distinct so the analyzer can retry a malformed answer without
    retrying a genuine outage.
    """


@dataclass(frozen=True, slots=True)
class Completion:
    """A model's answer plus what it cost.

    ``usage`` and ``model`` are recorded on the report so a reader can tell
    which model produced an analysis, and so spend is attributable.
    """

    text: str
    model: str
    usage: dict[str, Any] = field(default_factory=dict)


@runtime_checkable
class LLMProvider(Protocol):
    """What the analyzer requires of a language model."""

    @property
    def name(self) -> str:
        """Short identifier, e.g. ``groq``."""
        ...

    @property
    def model(self) -> str:
        """Model identifier recorded against every generated report."""
        ...

    async def complete(
        self,
        *,
        system: str,
        user: str,
        json_schema: dict[str, Any] | None = None,
    ) -> Completion:
        """Produce a completion.

        ``system`` carries the platform's instructions and ``user`` the case
        data. They are passed as separate messages rather than concatenated:
        keeping the instructions out of the same block as untrusted log text is
        the first line of defence against prompt injection.

        ``json_schema`` asks the provider for JSON output where it supports
        constrained decoding. It is a hint, not a guarantee -- the caller
        validates the result regardless.
        """
        ...
