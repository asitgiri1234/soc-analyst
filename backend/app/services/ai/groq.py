"""Groq as the language-model provider.

Groq exposes an OpenAI-compatible ``POST /chat/completions``, so the request
shape here is the familiar one. What matters for this platform is what the
provider guarantees to the layer above it:

*The key never leaves this module.* It is read from a ``SecretStr`` at the
moment of the request and written straight into a header. It is not logged, not
placed in an exception message, and not returned. Every error string this class
raises is scrubbed before it propagates, because a provider echoing a bad
Authorization header back in its own error body would otherwise put the key
into an API response.

*Failures are typed, not raw.* Transient statuses retry with backoff; a 401
does not, because repeating it cannot help. What is still broken afterwards
becomes an ``LLMError`` the endpoint turns into a 503.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from typing import Any

import httpx

from app.core.logging import get_logger
from app.services.ai.base import (
    Completion,
    LLMConfigurationError,
    LLMError,
)

logger = get_logger(__name__)

# Rate limiting and the transient 5xx family are worth another attempt. A 400
# or 401 means the request or the credential is wrong; repeating it only burns
# quota and delays the error the operator needs to see.
RETRYABLE_STATUS = frozenset({408, 425, 429, 500, 502, 503, 504})

# Belt and braces: if a key ever appears in text on its way out, redact it.
# Groq keys are `gsk_` followed by an alphanumeric body.
_KEY_PATTERN = re.compile(r"gsk_[A-Za-z0-9]{8,}")


def scrub(text: str, secret: str | None = None) -> str:
    """Remove anything key-shaped from a string bound for a log or an error."""
    cleaned = _KEY_PATTERN.sub("gsk_***REDACTED***", text)
    if secret:
        cleaned = cleaned.replace(secret, "***REDACTED***")
    return cleaned


@dataclass(frozen=True, slots=True)
class GroqProvider:
    """Calls Groq's chat completions endpoint."""

    model: str
    base_url: str
    api_key: str | None = None
    timeout_seconds: float = 60.0
    max_retries: int = 2
    max_output_tokens: int = 2048
    temperature: float = 0.2
    name: str = "groq"
    # Only the transport is injectable, never the whole client: the provider
    # must always build its own Authorization header, so that path is the one
    # under test rather than a stand-in.
    transport: httpx.AsyncBaseTransport | None = field(default=None, compare=False)

    async def complete(
        self,
        *,
        system: str,
        user: str,
        json_schema: dict[str, Any] | None = None,
    ) -> Completion:
        if not self.api_key:
            # Deliberately says which variable is missing and nothing about its
            # value, so the message is safe to surface to an operator.
            raise LLMConfigurationError(
                "GROQ_API_KEY is not set; the Groq provider cannot authenticate."
            )

        payload: dict[str, Any] = {
            "model": self.model,
            "messages": [
                # Two separate messages, never concatenated: the platform's
                # instructions and the untrusted case data stay in different
                # turns so the model can tell them apart.
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": self.temperature,
            "max_tokens": self.max_output_tokens,
        }
        if json_schema is not None:
            # JSON mode. The schema is also restated in the prompt, because
            # json_object mode constrains the syntax but not the shape.
            payload["response_format"] = {"type": "json_object"}

        data = await self._post(payload)
        return self._parse(data)

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            base_url=self.base_url,
            headers={"Authorization": f"Bearer {self.api_key}"},
            timeout=self.timeout_seconds,
            transport=self.transport,
        )

    async def _post(self, payload: dict[str, Any]) -> dict[str, Any]:
        """POST with bounded retries, converting every failure into LLMError."""
        last_error = "no attempt was made"

        async with self._client() as client:
            for attempt in range(self.max_retries + 1):
                try:
                    response = await client.post("/chat/completions", json=payload)
                except (httpx.TimeoutException, httpx.TransportError) as exc:
                    last_error = f"{type(exc).__name__}: {exc}"
                else:
                    if response.status_code == 200:
                        try:
                            return response.json()
                        except ValueError as exc:
                            raise LLMError(f"Groq returned a non-JSON body: {exc}") from exc

                    # The provider's body can echo request material; scrub it.
                    body = scrub(response.text[:300], self.api_key)
                    last_error = f"HTTP {response.status_code}: {body}"
                    if response.status_code not in RETRYABLE_STATUS:
                        raise LLMError(f"Groq rejected the request ({last_error})")

                if attempt < self.max_retries:
                    delay = 0.5 * (2**attempt)
                    logger.warning(
                        "Groq attempt %d/%d failed (%s); retrying in %.1fs",
                        attempt + 1,
                        self.max_retries + 1,
                        scrub(last_error, self.api_key),
                        delay,
                    )
                    await asyncio.sleep(delay)

        raise LLMError(
            f"Groq unavailable after {self.max_retries + 1} attempt(s): "
            f"{scrub(last_error, self.api_key)}"
        )

    def _parse(self, data: dict[str, Any]) -> Completion:
        """Pull the message text out of the response envelope."""
        choices = data.get("choices")
        if not isinstance(choices, list) or not choices:
            raise LLMError("Groq response contained no choices")

        message = choices[0].get("message") if isinstance(choices[0], dict) else None
        content = message.get("content") if isinstance(message, dict) else None
        if not isinstance(content, str) or not content.strip():
            raise LLMError("Groq response contained no message content")

        usage = data.get("usage")
        return Completion(
            text=content,
            model=str(data.get("model") or self.model),
            usage=usage if isinstance(usage, dict) else {},
        )
