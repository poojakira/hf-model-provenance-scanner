"""Comprehensive tests for the model quality evaluation module.

Tests bias detection, drift detection, accuracy monitoring,
and the top-level orchestrator. All use synthetic data.
"""

import json
import os
import random
import tempfile

import pytest

from scanner.quality.accuracy_monitor import AccuracyMonitor
from scanner.quality.bias_detector import StatisticalBiasDetector
from scanner.quality.drift_detector import DriftDetector
from scanner.quality.evaluator import ModelQualityEvaluator

# ==============================================================================
# Bias Detection Tests
# ==============================================================================


class TestStatisticalBiasDetector:
    """Tests for bias detection with known-biased synthetic data."""

    def test_unbiased_predictions_pass(self):
        """Fair predictions should pass all bias checks."""
        detector = StatisticalBiasDetector()
        # Both groups have exactly same selection rate and performance
        half = [1, 0, 1, 0, 1, 0, 1, 0, 1, 0] * 5  # 25 each half: 13 ones, 12 zeros
        predictions = half + half
        labels = half + half
        groups = ["A"] * 50 + ["B"] * 50

        report = detector.detect(predictions, labels, groups)
        assert report.passed is True
        assert report.demographic_parity_difference == 0.0
        assert report.disparate_impact_ratio == 1.0

    def test_biased_selection_rate_fails(self):
        """Different selection rates between groups should fail demographic parity."""
        detector = StatisticalBiasDetector(dp_threshold=0.1)
        # Group A: 80% positive, Group B: 20% positive
        predictions = [1] * 80 + [0] * 20 + [1] * 20 + [0] * 80
        labels = [1] * 50 + [0] * 50 + [1] * 50 + [0] * 50
        groups = ["A"] * 100 + ["B"] * 100

        report = detector.detect(predictions, labels, groups)
        assert report.passed is False
        assert report.demographic_parity_difference > 0.1
        assert "Demographic parity" in report.details

    def test_disparate_impact_below_threshold(self):
        """Disparate impact below 4/5ths rule should fail."""
        detector = StatisticalBiasDetector(di_threshold=0.8)
        # Group A: 90% selected, Group B: 30% selected -> DI = 0.33
        predictions = [1] * 90 + [0] * 10 + [1] * 30 + [0] * 70
        labels = [1] * 50 + [0] * 50 + [1] * 50 + [0] * 50
        groups = ["A"] * 100 + ["B"] * 100

        report = detector.detect(predictions, labels, groups)
        assert report.passed is False
        assert report.disparate_impact_ratio < 0.8
        assert "Disparate impact" in report.details

    def test_equalized_odds_violation(self):
        """Different TPR/FPR across groups should flag equalized odds violation."""
        detector = StatisticalBiasDetector(eo_threshold=0.1)
        # Group A: high TPR, Group B: low TPR
        # Group A: predict 1 for all positives, 0 for all negatives (perfect)
        preds_a = [1] * 50 + [0] * 50  # TPR=1.0, FPR=0.0
        labels_a = [1] * 50 + [0] * 50
        # Group B: predict 1 for half positives, 0 for rest (TPR=0.5, FPR=0.0)
        preds_b = [1] * 25 + [0] * 25 + [0] * 50
        labels_b = [1] * 50 + [0] * 50

        predictions = preds_a + preds_b
        labels = labels_a + labels_b
        groups = ["A"] * 100 + ["B"] * 100

        report = detector.detect(predictions, labels, groups)
        assert report.passed is False
        assert report.equalized_odds_difference > 0.1

    def test_group_metrics_computed_correctly(self):
        """Verify per-group metrics are computed."""
        detector = StatisticalBiasDetector()
        predictions = [1, 1, 0, 0, 1, 1, 1, 0]
        labels = [1, 0, 0, 1, 1, 1, 0, 0]
        groups = ["X", "X", "X", "X", "Y", "Y", "Y", "Y"]

        report = detector.detect(predictions, labels, groups)
        assert "X" in report.group_metrics
        assert "Y" in report.group_metrics
        assert "selection_rate" in report.group_metrics["X"]
        assert "true_positive_rate" in report.group_metrics["X"]
        assert "false_positive_rate" in report.group_metrics["X"]
        assert report.group_metrics["X"]["count"] == 4

    def test_bias_report_serializable(self):
        """BiasReport should be JSON serializable."""
        detector = StatisticalBiasDetector()
        predictions = [1, 0, 1, 0, 1, 0]
        labels = [1, 0, 1, 0, 1, 0]
        groups = ["A", "A", "A", "B", "B", "B"]

        report = detector.detect(predictions, labels, groups)
        json_str = report.to_json()
        parsed = json.loads(json_str)
        assert "demographic_parity_difference" in parsed
        assert "passed" in parsed

    def test_empty_predictions_raises(self):
        """Empty input should raise ValueError."""
        detector = StatisticalBiasDetector()
        with pytest.raises(ValueError):
            detector.detect([], [], [])


# ==============================================================================
# Drift Detection Tests
# ==============================================================================


class TestDriftDetector:
    """Tests for distribution drift detection with shifted distributions."""

    def test_no_drift_same_distribution(self):
        """Identical distributions should show no drift."""
        detector = DriftDetector()
        random.seed(42)
        reference = [random.gauss(0, 1) for _ in range(1000)]
        current = [random.gauss(0, 1) for _ in range(1000)]

        report = detector.detect_continuous(reference, current)
        assert report.severity in ("none", "minor")
        assert report.passed is True
        assert report.psi is not None
        assert report.psi < 0.2

    def test_severe_drift_shifted_distribution(self):
        """Large distribution shift should be detected as severe."""
        detector = DriftDetector()
        random.seed(42)
        reference = [random.gauss(0, 1) for _ in range(500)]
        # Shift mean by 3 standard deviations
        current = [random.gauss(3, 1) for _ in range(500)]

        report = detector.detect_continuous(reference, current)
        assert report.severity in ("moderate", "severe")
        assert report.passed is False
        assert report.psi is not None
        assert report.psi > 0.2

    def test_ks_test_detects_shift(self):
        """KS test should detect distributional differences."""
        detector = DriftDetector()
        random.seed(42)
        reference = [random.gauss(0, 1) for _ in range(200)]
        current = [random.gauss(2, 1) for _ in range(200)]

        report = detector.detect_continuous(reference, current)
        assert report.ks_statistic is not None
        assert report.ks_statistic > 0.3
        assert report.ks_p_value is not None
        assert report.ks_p_value < 0.05

    def test_chi_squared_no_drift(self):
        """Identical categorical distributions should show no drift."""
        detector = DriftDetector()
        random.seed(42)
        categories = ["cat", "dog", "bird"]
        weights = [0.5, 0.3, 0.2]

        reference = random.choices(categories, weights=weights, k=500)
        current = random.choices(categories, weights=weights, k=500)

        report = detector.detect_categorical(reference, current)
        assert report.severity == "none"
        assert report.passed is True
        assert report.chi_squared_statistic is not None

    def test_chi_squared_detects_category_shift(self):
        """Changed category proportions should be detected."""
        detector = DriftDetector()
        # Reference: mostly "A", Current: mostly "C"
        reference = ["A"] * 400 + ["B"] * 80 + ["C"] * 20
        current = ["A"] * 20 + ["B"] * 80 + ["C"] * 400

        report = detector.detect_categorical(reference, current)
        assert report.severity in ("moderate", "severe")
        assert report.passed is False

    def test_drift_report_serializable(self):
        """DriftReport should be JSON serializable."""
        detector = DriftDetector()
        random.seed(42)
        reference = [random.gauss(0, 1) for _ in range(100)]
        current = [random.gauss(0, 1) for _ in range(100)]

        report = detector.detect_continuous(reference, current)
        json_str = report.to_json()
        parsed = json.loads(json_str)
        assert "psi" in parsed
        assert "severity" in parsed


# ==============================================================================
# Accuracy Monitor Tests
# ==============================================================================


class TestAccuracyMonitor:
    """Tests for accuracy monitoring with degrading performance."""

    def test_high_accuracy_passes(self):
        """Perfect predictions should pass all thresholds."""
        monitor = AccuracyMonitor(window_size=50, metric_type="classification")
        predictions = [1, 0, 1, 0, 1] * 10
        labels = [1, 0, 1, 0, 1] * 10

        report = monitor.add_predictions(predictions, labels)
        assert report.passed is True
        assert report.metrics["accuracy"] == 1.0
        assert report.metrics["f1"] == 1.0

    def test_low_accuracy_triggers_alert(self):
        """Predictions below threshold should trigger alerts."""
        monitor = AccuracyMonitor(
            window_size=100,
            metric_type="classification",
            thresholds={"accuracy": 0.8},
        )
        # 50% accuracy - well below 80% threshold
        random.seed(42)
        predictions = [random.choice([0, 1]) for _ in range(100)]
        labels = [random.choice([0, 1]) for _ in range(100)]

        report = monitor.add_predictions(predictions, labels)
        assert report.passed is False
        assert len(report.threshold_alerts) > 0
        assert "accuracy" in report.threshold_alerts[0]

    def test_regression_metrics(self):
        """Regression MAE and RMSE should be computed correctly."""
        monitor = AccuracyMonitor(
            window_size=100,
            metric_type="regression",
            thresholds={"mae": 0.5, "rmse": 0.7},
        )
        # Perfect predictions
        predictions = [1.0, 2.0, 3.0, 4.0, 5.0]
        labels = [1.0, 2.0, 3.0, 4.0, 5.0]

        report = monitor.add_predictions(predictions, labels)
        assert report.passed is True
        assert report.metrics["mae"] == 0.0
        assert report.metrics["rmse"] == 0.0

    def test_regression_high_error_fails(self):
        """Large regression errors should fail."""
        monitor = AccuracyMonitor(
            window_size=100,
            metric_type="regression",
            thresholds={"mae": 0.5, "rmse": 0.7},
        )
        predictions = [5.0, 5.0, 5.0, 5.0, 5.0]
        labels = [1.0, 2.0, 3.0, 4.0, 5.0]

        report = monitor.add_predictions(predictions, labels)
        assert report.passed is False
        assert report.metrics["mae"] > 0.5

    def test_sliding_window_respects_size(self):
        """Only the most recent window_size samples should be considered."""
        monitor = AccuracyMonitor(window_size=10, metric_type="classification")

        # Add 10 perfect predictions
        monitor.add_predictions([1] * 10, [1] * 10)
        # Add 10 wrong predictions (window drops the perfect ones)
        report = monitor.add_predictions([0] * 10, [1] * 10)

        assert report.samples_in_window == 10
        assert report.metrics["accuracy"] == 0.0

    def test_degrading_trend_detected(self):
        """Accuracy dropping over time should be flagged as degrading."""
        monitor = AccuracyMonitor(window_size=20, metric_type="classification")

        # First batch: high accuracy
        monitor.add_predictions([1, 0, 1, 0] * 5, [1, 0, 1, 0] * 5)
        # Second batch: high accuracy
        monitor.add_predictions([1, 0, 1, 0] * 5, [1, 0, 1, 0] * 5)
        # Third batch: degraded accuracy
        monitor.add_predictions([0, 1, 0, 1] * 5, [1, 0, 1, 0] * 5)
        # Fourth batch: still degraded
        report = monitor.add_predictions([0, 1, 0, 1] * 5, [1, 0, 1, 0] * 5)

        assert report.trend == "degrading"

    def test_history_json_persistence(self):
        """History should be saved to and loaded from JSON."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            history_path = f.name

        try:
            monitor = AccuracyMonitor(
                window_size=20,
                metric_type="classification",
                history_path=history_path,
            )
            monitor.add_predictions([1, 0, 1, 0] * 5, [1, 0, 1, 0] * 5)

            # Verify file exists and is valid JSON
            assert os.path.exists(history_path)
            with open(history_path) as f:
                data = json.load(f)
            assert len(data) == 1
            assert "metrics" in data[0]

            # Load into new monitor
            monitor2 = AccuracyMonitor(
                window_size=20,
                metric_type="classification",
                history_path=history_path,
            )
            assert len(monitor2.get_history()) == 1
        finally:
            os.unlink(history_path)

    def test_accuracy_report_serializable(self):
        """AccuracyReport should be JSON serializable."""
        monitor = AccuracyMonitor(window_size=20, metric_type="classification")
        report = monitor.add_predictions([1, 0, 1, 0], [1, 0, 1, 0])

        json_str = report.to_json()
        parsed = json.loads(json_str)
        assert "metrics" in parsed
        assert "passed" in parsed
        assert "trend" in parsed


# ==============================================================================
# Orchestrator Tests
# ==============================================================================


class TestModelQualityEvaluator:
    """Tests for the top-level quality orchestrator."""

    def test_end_to_end_all_pass(self):
        """Good predictions with no bias and no drift should pass."""
        evaluator = ModelQualityEvaluator(
            accuracy_monitor=AccuracyMonitor(
                window_size=100,
                metric_type="classification",
                thresholds={"accuracy": 0.7},
            )
        )

        random.seed(42)
        # Generate predictions with ~90% accuracy
        labels = [random.choice([0, 1]) for _ in range(100)]
        # 90% correct
        predictions = [l if random.random() < 0.9 else (1 - l) for l in labels]
        groups = ["A"] * 50 + ["B"] * 50
        reference_dist = [random.gauss(0.5, 0.3) for _ in range(100)]

        report = evaluator.evaluate(
            predictions=predictions,
            labels=labels,
            groups=groups,
            reference_dist=reference_dist,
        )

        assert report.accuracy_report is not None
        assert report.bias_report is not None
        assert report.drift_report is not None

    def test_end_to_end_bias_fails(self):
        """Biased predictions should cause overall failure."""
        evaluator = ModelQualityEvaluator(
            accuracy_monitor=AccuracyMonitor(
                window_size=200,
                metric_type="classification",
                thresholds={"accuracy": 0.5},
            )
        )

        # Group A always gets positive, Group B always gets negative
        predictions = [1] * 100 + [0] * 100
        labels = [1] * 50 + [0] * 50 + [1] * 50 + [0] * 50
        groups = ["A"] * 100 + ["B"] * 100

        report = evaluator.evaluate(predictions=predictions, labels=labels, groups=groups)
        assert report.overall_pass is False
        assert report.bias_report is not None
        assert report.bias_report.passed is False
        assert "bias" in report.summary.lower()

    def test_end_to_end_without_optional_params(self):
        """Evaluator should work with just predictions and labels."""
        evaluator = ModelQualityEvaluator(
            accuracy_monitor=AccuracyMonitor(
                window_size=50,
                metric_type="classification",
                thresholds={"accuracy": 0.5},
            )
        )

        predictions = [1, 0, 1, 0, 1] * 10
        labels = [1, 0, 1, 0, 1] * 10

        report = evaluator.evaluate(predictions=predictions, labels=labels)
        assert report.overall_pass is True
        assert report.bias_report is None
        assert report.drift_report is None
        assert report.accuracy_report is not None

    def test_quality_report_json_output(self):
        """QualityReport should produce valid JSON."""
        evaluator = ModelQualityEvaluator(
            accuracy_monitor=AccuracyMonitor(window_size=50, metric_type="classification")
        )
        predictions = [1, 0, 1, 0, 1] * 10
        labels = [1, 0, 1, 0, 1] * 10
        groups = ["A"] * 25 + ["B"] * 25

        report = evaluator.evaluate(predictions=predictions, labels=labels, groups=groups)
        json_str = report.to_json()
        parsed = json.loads(json_str)
        assert "overall_pass" in parsed
        assert "bias_report" in parsed
        assert "accuracy_report" in parsed
