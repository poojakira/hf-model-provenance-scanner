"""Statistical bias detection for model predictions.

Computes fairness metrics without any ML dependencies - pure statistical
computation on prediction arrays and demographic group labels.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass


@dataclass
class BiasReport:
    """Report of bias detection results."""

    demographic_parity_difference: float
    equalized_odds_difference: float
    disparate_impact_ratio: float
    group_metrics: dict[str, dict[str, float]]
    passed: bool
    thresholds: dict[str, float]
    details: str = ""

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


class StatisticalBiasDetector:
    """Detect statistical bias in model predictions across demographic groups.

    Args:
        dp_threshold: Maximum allowed demographic parity difference (default 0.1).
        eo_threshold: Maximum allowed equalized odds difference (default 0.1).
        di_threshold: Minimum allowed disparate impact ratio (default 0.8).
    """

    def __init__(
        self,
        dp_threshold: float = 0.1,
        eo_threshold: float = 0.1,
        di_threshold: float = 0.8,
    ):
        self.dp_threshold = dp_threshold
        self.eo_threshold = eo_threshold
        self.di_threshold = di_threshold

    def detect(
        self,
        predictions: list[int],
        labels: list[int],
        groups: list[str],
    ) -> BiasReport:
        """Run bias detection on predictions with demographic group labels.

        Args:
            predictions: Binary predictions (0 or 1).
            labels: True binary labels (0 or 1).
            groups: Demographic group label for each sample.

        Returns:
            BiasReport with computed metrics and pass/fail determination.
        """
        if len(predictions) != len(labels) or len(predictions) != len(groups):
            raise ValueError("predictions, labels, and groups must have the same length")

        if len(predictions) == 0:
            raise ValueError("Cannot compute bias on empty arrays")

        # Compute per-group metrics
        group_metrics = self._compute_group_metrics(predictions, labels, groups)

        # Compute fairness metrics
        dp_diff = self._demographic_parity_difference(predictions, groups)
        eo_diff = self._equalized_odds_difference(predictions, labels, groups)
        di_ratio = self._disparate_impact_ratio(predictions, groups)

        # Determine pass/fail
        passed = (
            abs(dp_diff) <= self.dp_threshold
            and abs(eo_diff) <= self.eo_threshold
            and di_ratio >= self.di_threshold
        )

        details_parts = []
        if abs(dp_diff) > self.dp_threshold:
            details_parts.append(
                f"Demographic parity difference {dp_diff:.4f} exceeds threshold {self.dp_threshold}"
            )
        if abs(eo_diff) > self.eo_threshold:
            details_parts.append(
                f"Equalized odds difference {eo_diff:.4f} exceeds threshold {self.eo_threshold}"
            )
        if di_ratio < self.di_threshold:
            details_parts.append(
                f"Disparate impact ratio {di_ratio:.4f} below threshold {self.di_threshold}"
            )

        return BiasReport(
            demographic_parity_difference=dp_diff,
            equalized_odds_difference=eo_diff,
            disparate_impact_ratio=di_ratio,
            group_metrics=group_metrics,
            passed=passed,
            thresholds={
                "demographic_parity": self.dp_threshold,
                "equalized_odds": self.eo_threshold,
                "disparate_impact": self.di_threshold,
            },
            details="; ".join(details_parts)
            if details_parts
            else "All fairness metrics within thresholds",
        )

    def _compute_group_metrics(
        self,
        predictions: list[int],
        labels: list[int],
        groups: list[str],
    ) -> dict[str, dict[str, float]]:
        """Compute per-group selection rate, TPR, FPR."""
        unique_groups = sorted(set(groups))
        metrics: dict[str, dict[str, float]] = {}

        for group in unique_groups:
            group_preds = [p for p, g in zip(predictions, groups, strict=False) if g == group]
            group_labels = [l for l, g in zip(labels, groups, strict=False) if g == group]

            n = len(group_preds)
            positive_preds = sum(group_preds)
            selection_rate = positive_preds / n if n > 0 else 0.0

            # True positive rate (recall)
            true_positives = sum(
                1 for p, l in zip(group_preds, group_labels, strict=False) if p == 1 and l == 1
            )
            actual_positives = sum(group_labels)
            tpr = true_positives / actual_positives if actual_positives > 0 else 0.0

            # False positive rate
            false_positives = sum(
                1 for p, l in zip(group_preds, group_labels, strict=False) if p == 1 and l == 0
            )
            actual_negatives = n - actual_positives
            fpr = false_positives / actual_negatives if actual_negatives > 0 else 0.0

            metrics[group] = {
                "count": n,
                "selection_rate": selection_rate,
                "true_positive_rate": tpr,
                "false_positive_rate": fpr,
            }

        return metrics

    def _demographic_parity_difference(self, predictions: list[int], groups: list[str]) -> float:
        """Compute max difference in selection rates between groups.

        Demographic parity requires that the selection rate (P(Y_hat=1))
        is the same across all groups.
        """
        unique_groups = sorted(set(groups))
        selection_rates = []

        for group in unique_groups:
            group_preds = [p for p, g in zip(predictions, groups, strict=False) if g == group]
            n = len(group_preds)
            if n > 0:
                selection_rates.append(sum(group_preds) / n)

        if len(selection_rates) < 2:
            return 0.0

        return max(selection_rates) - min(selection_rates)

    def _equalized_odds_difference(
        self, predictions: list[int], labels: list[int], groups: list[str]
    ) -> float:
        """Compute max equalized odds difference.

        Equalized odds requires that TPR and FPR are equal across groups.
        Returns the maximum of (max TPR diff, max FPR diff).
        """
        unique_groups = sorted(set(groups))
        tprs = []
        fprs = []

        for group in unique_groups:
            group_preds = [p for p, g in zip(predictions, groups, strict=False) if g == group]
            group_labels = [l for l, g in zip(labels, groups, strict=False) if g == group]

            true_positives = sum(
                1 for p, l in zip(group_preds, group_labels, strict=False) if p == 1 and l == 1
            )
            actual_positives = sum(group_labels)
            tpr = true_positives / actual_positives if actual_positives > 0 else 0.0

            false_positives = sum(
                1 for p, l in zip(group_preds, group_labels, strict=False) if p == 1 and l == 0
            )
            actual_negatives = len(group_labels) - actual_positives
            fpr = false_positives / actual_negatives if actual_negatives > 0 else 0.0

            tprs.append(tpr)
            fprs.append(fpr)

        if len(tprs) < 2:
            return 0.0

        tpr_diff = max(tprs) - min(tprs)
        fpr_diff = max(fprs) - min(fprs)
        return max(tpr_diff, fpr_diff)

    def _disparate_impact_ratio(self, predictions: list[int], groups: list[str]) -> float:
        """Compute disparate impact ratio (min selection rate / max selection rate).

        The 4/5ths rule: ratio should be >= 0.8.
        Returns 1.0 if max selection rate is 0.
        """
        unique_groups = sorted(set(groups))
        selection_rates = []

        for group in unique_groups:
            group_preds = [p for p, g in zip(predictions, groups, strict=False) if g == group]
            n = len(group_preds)
            if n > 0:
                selection_rates.append(sum(group_preds) / n)

        if len(selection_rates) < 2:
            return 1.0

        max_rate = max(selection_rates)
        min_rate = min(selection_rates)

        if max_rate == 0:
            return 1.0

        return min_rate / max_rate
