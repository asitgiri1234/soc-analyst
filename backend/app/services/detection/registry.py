"""The set of detectors the engine will run.

Detectors are registered by name rather than hard-coded into the engine, so
adding one -- including an ML-backed one in a later phase -- means writing a
class with a ``detect`` method and registering it. No change to the engine, the
endpoint, the request schema or the stored shape of an anomaly.
"""

from __future__ import annotations

from app.services.detection.detectors.brute_force import BruteForceDetector
from app.services.detection.detectors.event_burst import EventBurstDetector
from app.services.detection.detectors.request_frequency import RequestFrequencyDetector
from app.services.detection.detectors.suspicious_ip import SuspiciousIPDetector
from app.services.detection.types import Detector

# Instances, not classes: each carries its own thresholds, and a deployment can
# register the same detector twice with different tuning if it needs to.
_DEFAULT_DETECTORS: tuple[Detector, ...] = (
    BruteForceDetector(),
    RequestFrequencyDetector(),
    SuspiciousIPDetector(),
    EventBurstDetector(),
)

_registry: dict[str, Detector] = {detector.name: detector for detector in _DEFAULT_DETECTORS}


def register(detector: Detector) -> None:
    """Add or replace a detector. Registering the same name twice replaces it."""
    _registry[detector.name] = detector


def unregister(name: str) -> None:
    _registry.pop(name, None)


def reset() -> None:
    """Restore the built-in set, for tests that register their own."""
    _registry.clear()
    _registry.update({detector.name: detector for detector in _DEFAULT_DETECTORS})


def available() -> list[str]:
    return sorted(_registry)


def get(name: str) -> Detector | None:
    return _registry.get(name)


def resolve(names: list[str] | None = None) -> list[Detector]:
    """The detectors to run.

    ``None`` means all of them. An unknown name raises rather than being
    ignored: a caller asking for a detector that does not exist has a typo, and
    silently returning fewer results would hide it.
    """
    if names is None:
        return [_registry[name] for name in sorted(_registry)]

    unknown = [name for name in names if name not in _registry]
    if unknown:
        raise KeyError(f"unknown detector(s): {', '.join(sorted(unknown))}")
    return [_registry[name] for name in names]
