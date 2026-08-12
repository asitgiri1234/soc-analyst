"""Robust statistics for the outlier detectors.

The mean and standard deviation are the obvious tools and the wrong ones here:
the outlier being looked for is itself in the sample, and it drags both upward
until it no longer looks unusual. One host sending 10,000 events pulls the mean
up far enough to hide itself.

The median and the median absolute deviation do not move that way, so a single
extreme value stays extreme. That is why the detectors report a *modified*
z-score, computed from the median rather than the mean.
"""

from __future__ import annotations

from collections.abc import Sequence
from statistics import median

# Scaling constant that puts the modified z-score on the same footing as an
# ordinary one for normally distributed data (Iglewicz and Hoaglin).
_MAD_SCALE = 0.6745


def median_absolute_deviation(values: Sequence[float]) -> float:
    """Median of the absolute deviations from the median."""
    if not values:
        return 0.0
    centre = median(values)
    return float(median([abs(value - centre) for value in values]))


def modified_z_score(value: float, values: Sequence[float]) -> float:
    """How far ``value`` sits from the population's median, in robust units.

    When the MAD is zero -- every entity behaving identically, which is common
    in quiet traffic -- the scale is undefined. The fallback is the mean
    absolute deviation, and if that is zero too the population is genuinely
    uniform and nothing can be an outlier.
    """
    if not values:
        return 0.0
    centre = median(values)
    deviation = median_absolute_deviation(values)

    if deviation > 0:
        return _MAD_SCALE * (value - centre) / deviation

    mean_deviation = sum(abs(item - centre) for item in values) / len(values)
    if mean_deviation > 0:
        return 0.7979 * (value - centre) / mean_deviation

    return 0.0


def summarise(values: Sequence[float]) -> dict[str, float]:
    """The baseline figures a finding quotes, so the arithmetic is checkable."""
    if not values:
        return {"count": 0, "median": 0.0, "mad": 0.0, "max": 0.0}
    return {
        "count": len(values),
        "median": round(float(median(values)), 4),
        "mad": round(median_absolute_deviation(values), 4),
        "max": round(float(max(values)), 4),
    }
