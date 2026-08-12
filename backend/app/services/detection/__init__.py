"""Anomaly detection over normalised log entries.

V1 is rule and statistics based, and every finding is explainable: it carries
the reason in words, the evidence behind it, and the numbers the score came
from. Nothing here calls an external model.

The layering is what makes that replaceable later:

``types``       the Detector protocol, findings, and the score-to-severity map
``signals``     reading intent (failure, block, actor) out of an entry
``statistics``  robust outlier maths
``detectors/``  the individual detectors, pure and independently testable
``registry``    which detectors exist
``engine``      loads a window, runs them, persists what they find

An ML detector added later implements the same protocol and registers itself.
The engine, the endpoint and the Anomaly schema do not change.
"""

from app.services.detection.engine import AnalysisResult, analyze
from app.services.detection.types import DetectionContext, Detector, Finding

__all__ = ["AnalysisResult", "DetectionContext", "Detector", "Finding", "analyze"]
