"""A local, deterministic embedding provider.

No API key, no network, no cost, and the same text always produces the same
vector -- which is what makes it usable as the default for development and for
the entire test suite.

It is a hashed bag-of-words projection: each token is hashed to a small set of
dimensions and accumulated, then the vector is L2-normalised so cosine
similarity is a dot product. That captures *lexical* overlap, which is enough
for the pipeline to be exercised end to end and for "SSH brute force" to
retrieve the SSH brute force playbook.

What it does not capture is meaning: it will not connect "credential stuffing"
to "password reuse attack" the way a trained model does. It is a working
default and a test fixture, not a substitute for a real embedding model in
production -- point EMBEDDING_PROVIDER at ``http`` for that.
"""

from __future__ import annotations

import hashlib
import math
import re
from collections.abc import Sequence
from dataclasses import dataclass

# Tokens: runs of letters/digits, lower-cased. Good enough for lexical overlap.
_TOKEN = re.compile(r"[a-z0-9]+")

# Each token contributes to this many dimensions. More than one reduces the
# damage from any single hash collision.
_HASHES_PER_TOKEN = 3


@dataclass(frozen=True, slots=True)
class HashingEmbeddingProvider:
    """Deterministic lexical embeddings, computed locally."""

    dimensions: int
    name: str = "hashing"
    model: str = "hashing-v1"

    async def embed(self, texts: Sequence[str]) -> list[list[float]]:
        return [self._vector(text) for text in texts]

    async def embed_query(self, text: str) -> list[float]:
        # Symmetric model: a query is embedded exactly like a document.
        return self._vector(text)

    def _vector(self, text: str) -> list[float]:
        vector = [0.0] * self.dimensions
        tokens = _TOKEN.findall(text.lower())

        for token in tokens:
            for slot in range(_HASHES_PER_TOKEN):
                digest = hashlib.blake2b(
                    f"{slot}:{token}".encode(), digest_size=8
                ).digest()
                index = int.from_bytes(digest[:4], "big") % self.dimensions
                # The last bit picks a sign, so unrelated tokens are as likely
                # to cancel as to reinforce and vectors stay near-orthogonal.
                sign = 1.0 if digest[4] & 1 else -1.0
                vector[index] += sign

        norm = math.sqrt(sum(value * value for value in vector))
        if norm == 0.0:
            # No tokens at all (empty or punctuation-only text). A zero vector
            # is a valid answer: it has no similarity to anything.
            return vector
        return [value / norm for value in vector]
