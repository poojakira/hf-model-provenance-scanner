"""Accuracy monitoring with sliding window and trend analysis.

Supports classification metrics (accuracy, F1, precision, recall) and
regression metrics (MAE, RMSE). Stores history in JSON for trend analysis.
"""

from __future__ import annotations

import json
import math
import os
import time
from collections import deque
from dataclasses import asdict, dataclass
from typing import Literal


@dataclass
class AccuracyReport:
    """Report of accuracy monitoring results."""

    metric_type: str  # "classification" or "regression"
    metrics: dict[str, float]
    window_size: int
    samples_in_window: int
    threshold_alerts: list[str]
    passed: bool
    trend: str = ""  # "stable", "improving", "degrading"

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


class AccuracyMonitor:
    """Track model accuracy over time with sliding window computation.

    Args:
        window_size: Number of recent samples to evaluate (default 100).
        metric_type: "classification" or "regression".
        thresholds: Dict of metric_name -> minimum acceptable value.
            For regression metrics (MAE, RMSE), these are maximum acceptable values.
        history_path: Optional path to JSON file for storing history.
    """

    def __init__(
        self,
        window_size: int = 100,
        metric_type: Literal["classification", "regression"] = "classification",
        thresholds: dict[str, float] | None = None,
        history_path: str | None = None,
    ):
        self.window_size = window_size
        self.metric_type = metric_type
        self.thresholds = thresholds or self._default_thresholds()
        self.history_path = history_path

        self._predictions: deque = deque(maxlen=window_size)
        self._labels: deque = deque(maxlen=window_size)
        self._history: list[dict] = []

        if history_path and os.path.exists(history_path):
            self._load_history()

    def _default_thresholds(self) -> dict[str, float]:
        if self.metric_type == "classification":
            return {"accuracy": 0.7, "f1": 0.6, "precision": 0.6, "recall": 0.6}
        else:
            return {"mae": 1.0, "rmse": 1.5}

    def add_predictions(self, predictions: list, labels: list) -> AccuracyReport:
        """Add new predictions and labels to the sliding window.

        Args:
            predictions: New predictions to add.
            labels: Corresponding true labels.

        Returns:
            AccuracyReport with current window metrics.
        """
        if len(predictions) != len(labels):
            raise ValueError("predictions and labels must have the same length")

        for p, l in zip(predictions, labels, strict=False):
            self._predictions.append(p)
            self._labels.append(l)

        return self.evaluate()

    def evaluate(self) -> AccuracyReport:
        """Evaluate current window metrics.

        Returns:
            AccuracyReport with computed metrics, alerts, and trend.
        """
        preds = list(self._predictions)
        labs = list(self._labels)

        if len(preds) == 0:
            return AccuracyReport(
                metric_type=self.metric_type,
                metrics={},
                window_size=self.window_size,
                samples_in_window=0,
                threshold_alerts=["No data in window"],
                passed=False,
                trend="unknown",
            )

        if self.metric_type == "classification":
            metrics = self._compute_classification_metrics(preds, labs)
        else:
            metrics = self._compute_regression_metrics(preds, labs)

        # Check thresholds
        alerts = self._check_thresholds(metrics)
        passed = len(alerts) == 0

        # Compute trend
        trend = self._compute_trend(metrics)

        # Store in history
        entry = {
            "timestamp": time.time(),
            "metrics": metrics,
            "samples_in_window": len(preds),
            "passed": passed,
        }
        self._history.append(entry)
        if self.history_path:
            self._save_history()

        return AccuracyReport(
            metric_type=self.metric_type,
            metrics=metrics,
            window_size=self.window_size,
            samples_in_window=len(preds),
            threshold_alerts=alerts,
            passed=passed,
            trend=trend,
        )

    def _compute_classification_metrics(
        self, predictions: list[int], labels: list[int]
    ) -> dict[str, float]:
        """Compute classification metrics: accuracy, F1, precision, recall."""
        n = len(predictions)
        if n == 0:
            return {"accuracy": 0.0, "f1": 0.0, "precision": 0.0, "recall": 0.0}

        correct = sum(1 for p, l in zip(predictions, labels, strict=False) if p == l)
        accuracy = correct / n

        # Binary metrics (treat as binary or use micro-averaging)
        unique_labels = sorted(set(labels + predictions))

        if len(unique_labels) <= 2:
            # Binary case
            tp = sum(1 for p, l in zip(predictions, labels, strict=False) if p == 1 and l == 1)
            fp = sum(1 for p, l in zip(predictions, labels, strict=False) if p == 1 and l == 0)
            fn = sum(1 for p, l in zip(predictions, labels, strict=False) if p == 0 and l == 1)

            precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
        else:
            # Multiclass: macro-averaged
            precisions = []
            recalls = []
            for cls in unique_labels:
                tp = sum(
                    1 for p, l in zip(predictions, labels, strict=False) if p == cls and l == cls
                )
                fp = sum(
                    1 for p, l in zip(predictions, labels, strict=False) if p == cls and l != cls
                )
                fn = sum(
                    1 for p, l in zip(predictions, labels, strict=False) if p != cls and l == cls
                )
                p = tp / (tp + fp) if (tp + fp) > 0 else 0.0
                r = tp / (tp + fn) if (tp + fn) > 0 else 0.0
                precisions.append(p)
                recalls.append(r)

            precision = sum(precisions) / len(precisions) if precisions else 0.0
            recall = sum(recalls) / len(recalls) if recalls else 0.0
            f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

        return {
            "accuracy": accuracy,
            "f1": f1,
            "precision": precision,
            "recall": recall,
        }

    def _compute_regression_metrics(
        self, predictions: list[float], labels: list[float]
    ) -> dict[str, float]:
        """Compute regression metrics: MAE, RMSE."""
        n = len(predictions)
        if n == 0:
            return {"mae": 0.0, "rmse": 0.0}

        errors = [abs(p - l) for p, l in zip(predictions, labels, strict=False)]
        mae = sum(errors) / n

        squared_errors = [(p - l) ** 2 for p, l in zip(predictions, labels, strict=False)]
        rmse = math.sqrt(sum(squared_errors) / n)

        return {"mae": mae, "rmse": rmse}

    def _check_thresholds(self, metrics: dict[str, float]) -> list[str]:
        """Check metrics against thresholds and return alerts."""
        alerts = []
        for metric_name, threshold in self.thresholds.items():
            if metric_name not in metrics:
                continue

            value = metrics[metric_name]
            if self.metric_type == "regression":
                # For regression, threshold is max acceptable
                if value > threshold:
                    alerts.append(f"{metric_name}={value:.4f} exceeds threshold {threshold}")
            else:
                # For classification, threshold is min acceptable
                if value < threshold:
                    alerts.append(f"{metric_name}={value:.4f} below threshold {threshold}")

        return alerts

    def _compute_trend(self, current_metrics: dict[str, float]) -> str:
        """Determine trend from history."""
        if len(self._history) < 2:
            return "stable"

        # Look at primary metric over recent history
        primary_metric = "accuracy" if self.metric_type == "classification" else "mae"
        recent = self._history[-5:] if len(self._history) >= 5 else self._history

        values = [entry["metrics"].get(primary_metric, 0) for entry in recent]

        if len(values) < 2:
            return "stable"

        # Simple trend detection: compare first half to second half
        mid = len(values) // 2
        first_half_avg = sum(values[:mid]) / mid if mid > 0 else 0
        second_half_avg = sum(values[mid:]) / (len(values) - mid) if (len(values) - mid) > 0 else 0

        threshold = 0.02  # 2% change threshold

        if self.metric_type == "regression":
            # For regression, lower is better
            if second_half_avg < first_half_avg - threshold:
                return "improving"
            elif second_half_avg > first_half_avg + threshold:
                return "degrading"
        else:
            # For classification, higher is better
            if second_half_avg > first_half_avg + threshold:
                return "improving"
            elif second_half_avg < first_half_avg - threshold:
                return "degrading"

        return "stable"

    def get_history(self) -> list[dict]:
        """Return the full history of evaluations."""
        return self._history.copy()

    def _save_history(self) -> None:
        """Save history to JSON file."""
        if self.history_path:
            with open(self.history_path, "w") as f:
                json.dump(self._history, f, indent=2)

    def _load_history(self) -> None:
        """Load history from JSON file."""
        if self.history_path and os.path.exists(self.history_path):
            with open(self.history_path) as f:
                content = f.read().strip()
                if content:
                    self._history = json.loads(content)
                else:
                    self._history = []
