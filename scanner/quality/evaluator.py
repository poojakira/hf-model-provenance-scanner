"""Top-level model quality evaluation orchestrator.

Combines bias detection, drift detection, and accuracy monitoring
into a single evaluation pipeline with unified reporting.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from scanner.quality.accuracy_monitor import AccuracyMonitor, AccuracyReport
from scanner.quality.bias_detector import BiasReport, StatisticalBiasDetector
from scanner.quality.drift_detector import DriftDetector, DriftReport


@dataclass
class QualityReport:
    """Unified quality evaluation report."""

    overall_pass: bool
    bias_report: BiasReport | None = None
    drift_report: DriftReport | None = None
    accuracy_report: AccuracyReport | None = None
    summary: str = ""

    def to_dict(self) -> dict:
        result = {
            "overall_pass": self.overall_pass,
            "summary": self.summary,
            "bias_report": self.bias_report.to_dict() if self.bias_report else None,
            "drift_report": self.drift_report.to_dict() if self.drift_report else None,
            "accuracy_report": self.accuracy_report.to_dict() if self.accuracy_report else None,
        }
        return result

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


class ModelQualityEvaluator:
    """Orchestrate model quality evaluation across multiple dimensions.

    Args:
        bias_detector: Optional custom StatisticalBiasDetector instance.
        drift_detector: Optional custom DriftDetector instance.
        accuracy_monitor: Optional custom AccuracyMonitor instance.
    """

    def __init__(
        self,
        bias_detector: StatisticalBiasDetector | None = None,
        drift_detector: DriftDetector | None = None,
        accuracy_monitor: AccuracyMonitor | None = None,
    ):
        self.bias_detector = bias_detector or StatisticalBiasDetector()
        self.drift_detector = drift_detector or DriftDetector()
        self.accuracy_monitor = accuracy_monitor or AccuracyMonitor()

    def evaluate(
        self,
        predictions: list,
        labels: list,
        groups: list[str] | None = None,
        reference_dist: list[float] | None = None,
    ) -> QualityReport:
        """Run full quality evaluation.

        Args:
            predictions: Model predictions.
            labels: True labels.
            groups: Optional demographic group labels for bias detection.
            reference_dist: Optional reference distribution for drift detection.

        Returns:
            QualityReport with results from all evaluations.
        """
        bias_report = None
        drift_report = None
        accuracy_report = None

        issues = []

        # Accuracy monitoring (always runs)
        accuracy_report = self.accuracy_monitor.add_predictions(predictions, labels)
        if not accuracy_report.passed:
            issues.append("accuracy degradation detected")

        # Bias detection (only if groups provided)
        if groups is not None:
            try:
                bias_report = self.bias_detector.detect(predictions, labels, groups)
                if not bias_report.passed:
                    issues.append("bias detected")
            except ValueError:
                pass

        # Drift detection (only if reference distribution provided)
        if reference_dist is not None:
            try:
                # Convert predictions to float for drift comparison
                current_dist = [float(p) for p in predictions]
                drift_report = self.drift_detector.detect_continuous(reference_dist, current_dist)
                if not drift_report.passed:
                    issues.append(f"distribution drift detected (severity={drift_report.severity})")
            except ValueError:
                pass

        overall_pass = len(issues) == 0

        summary = "All quality checks passed" if overall_pass else f"Issues: {'; '.join(issues)}"

        return QualityReport(
            overall_pass=overall_pass,
            bias_report=bias_report,
            drift_report=drift_report,
            accuracy_report=accuracy_report,
            summary=summary,
        )
