"""Distribution drift detection.

Implements Population Stability Index (PSI), Kolmogorov-Smirnov test,
and Chi-squared test from scratch using only stdlib.
"""

from __future__ import annotations

import json
import math
from collections import Counter
from dataclasses import asdict, dataclass


@dataclass
class DriftReport:
    """Report of distribution drift detection results."""

    psi: float | None
    ks_statistic: float | None
    ks_p_value: float | None
    chi_squared_statistic: float | None
    chi_squared_p_value: float | None
    severity: str  # none, minor, moderate, severe
    passed: bool
    details: str = ""

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


class DriftDetector:
    """Detect distribution drift between reference and current distributions.

    Args:
        psi_thresholds: Tuple of (minor, moderate, severe) PSI thresholds.
        ks_alpha: Significance level for KS test (default 0.05).
        chi2_alpha: Significance level for chi-squared test (default 0.05).
        n_bins: Number of bins for PSI computation (default 10).
    """

    def __init__(
        self,
        psi_thresholds: tuple[float, float, float] = (0.1, 0.2, 0.5),
        ks_alpha: float = 0.05,
        chi2_alpha: float = 0.05,
        n_bins: int = 10,
    ):
        self.psi_minor, self.psi_moderate, self.psi_severe = psi_thresholds
        self.ks_alpha = ks_alpha
        self.chi2_alpha = chi2_alpha
        self.n_bins = n_bins

    def detect_continuous(self, reference: list[float], current: list[float]) -> DriftReport:
        """Detect drift for continuous features using PSI and KS test.

        Args:
            reference: Reference distribution values.
            current: Current distribution values.

        Returns:
            DriftReport with PSI, KS test results, and severity.
        """
        if len(reference) == 0 or len(current) == 0:
            raise ValueError("Reference and current distributions must be non-empty")

        psi = self._compute_psi(reference, current)
        ks_stat, ks_p = self._ks_test(reference, current)

        severity = self._psi_severity(psi)

        # Also consider KS test for severity
        if ks_p is not None and ks_p < self.ks_alpha and severity == "none":
            severity = "minor"

        passed = severity in ("none", "minor")

        details_parts = []
        details_parts.append(f"PSI={psi:.4f} (severity={severity})")
        if ks_p is not None:
            details_parts.append(f"KS statistic={ks_stat:.4f}, p-value={ks_p:.4f}")

        return DriftReport(
            psi=psi,
            ks_statistic=ks_stat,
            ks_p_value=ks_p,
            chi_squared_statistic=None,
            chi_squared_p_value=None,
            severity=severity,
            passed=passed,
            details="; ".join(details_parts),
        )

    def detect_categorical(self, reference: list[str], current: list[str]) -> DriftReport:
        """Detect drift for categorical features using chi-squared test.

        Args:
            reference: Reference distribution categories.
            current: Current distribution categories.

        Returns:
            DriftReport with chi-squared test results and severity.
        """
        if len(reference) == 0 or len(current) == 0:
            raise ValueError("Reference and current distributions must be non-empty")

        chi2_stat, chi2_p, dof = self._chi_squared_test(reference, current)

        # Determine severity from p-value
        if chi2_p > 0.1:
            severity = "none"
        elif chi2_p > 0.01:
            severity = "minor"
        elif chi2_p > 0.001:
            severity = "moderate"
        else:
            severity = "severe"

        passed = severity in ("none", "minor")

        details = f"Chi-squared statistic={chi2_stat:.4f}, p-value={chi2_p:.6f}, dof={dof}"

        return DriftReport(
            psi=None,
            ks_statistic=None,
            ks_p_value=None,
            chi_squared_statistic=chi2_stat,
            chi_squared_p_value=chi2_p,
            severity=severity,
            passed=passed,
            details=details,
        )

    def _compute_psi(self, reference: list[float], current: list[float]) -> float:
        """Compute Population Stability Index between two distributions."""
        # Create bins from reference distribution
        ref_sorted = sorted(reference)
        n = len(ref_sorted)
        bin_edges = []

        for i in range(self.n_bins + 1):
            idx = int(i * (n - 1) / self.n_bins)
            bin_edges.append(ref_sorted[idx])

        # Ensure first/last edges cover full range
        all_values = reference + current
        bin_edges[0] = min(all_values) - 1e-10
        bin_edges[-1] = max(all_values) + 1e-10

        # Remove duplicate edges
        unique_edges = [bin_edges[0]]
        for e in bin_edges[1:]:
            if e > unique_edges[-1]:
                unique_edges.append(e)
        bin_edges = unique_edges

        actual_bins = len(bin_edges) - 1
        if actual_bins < 1:
            return 0.0

        # Count in bins
        ref_counts = [0] * actual_bins
        cur_counts = [0] * actual_bins

        for val in reference:
            for i in range(actual_bins):
                if val <= bin_edges[i + 1] or i == actual_bins - 1:
                    ref_counts[i] += 1
                    break

        for val in current:
            for i in range(actual_bins):
                if val <= bin_edges[i + 1] or i == actual_bins - 1:
                    cur_counts[i] += 1
                    break

        # Compute PSI
        ref_total = sum(ref_counts)
        cur_total = sum(cur_counts)

        if ref_total == 0 or cur_total == 0:
            return 0.0

        psi = 0.0
        epsilon = 1e-6

        for i in range(actual_bins):
            ref_pct = (ref_counts[i] + epsilon) / (ref_total + epsilon * actual_bins)
            cur_pct = (cur_counts[i] + epsilon) / (cur_total + epsilon * actual_bins)
            psi += (cur_pct - ref_pct) * math.log(cur_pct / ref_pct)

        return psi

    def _ks_test(self, reference: list[float], current: list[float]) -> tuple[float, float]:
        """Compute two-sample Kolmogorov-Smirnov test statistic and approximate p-value."""
        ref_sorted = sorted(reference)
        cur_sorted = sorted(current)
        n1 = len(ref_sorted)
        n2 = len(cur_sorted)

        # Merge and compute empirical CDFs
        all_values = sorted(set(ref_sorted + cur_sorted))
        max_diff = 0.0

        for val in all_values:
            # CDF of reference at val
            cdf1 = self._ecdf_at(ref_sorted, val)
            # CDF of current at val
            cdf2 = self._ecdf_at(cur_sorted, val)
            diff = abs(cdf1 - cdf2)
            if diff > max_diff:
                max_diff = diff

        # Approximate p-value using asymptotic formula
        en = math.sqrt(n1 * n2 / (n1 + n2))
        lambda_val = (en + 0.12 + 0.11 / en) * max_diff

        # Kolmogorov distribution approximation
        p_value = self._kolmogorov_p_value(lambda_val)

        return max_diff, p_value

    def _ecdf_at(self, sorted_values: list[float], x: float) -> float:
        """Compute empirical CDF at point x for sorted values."""
        n = len(sorted_values)
        count = 0
        for v in sorted_values:
            if v <= x:
                count += 1
            else:
                break
        return count / n

    def _kolmogorov_p_value(self, lambda_val: float) -> float:
        """Approximate p-value for Kolmogorov distribution."""
        if lambda_val <= 0:
            return 1.0
        if lambda_val >= 3.0:
            return 0.0

        # Approximation using series expansion
        # P(K > lambda) = 2 * sum_{k=1}^{inf} (-1)^{k-1} * exp(-2*k^2*lambda^2)
        p = 0.0
        for k in range(1, 100):
            term = ((-1) ** (k - 1)) * math.exp(-2.0 * k * k * lambda_val * lambda_val)
            p += term
            if abs(term) < 1e-12:
                break

        p_value = 2.0 * p
        return max(0.0, min(1.0, p_value))

    def _chi_squared_test(
        self, reference: list[str], current: list[str]
    ) -> tuple[float, float, int]:
        """Compute chi-squared test between two categorical distributions."""
        ref_counts = Counter(reference)
        cur_counts = Counter(current)

        # Get all categories
        all_categories = sorted(set(list(ref_counts.keys()) + list(cur_counts.keys())))

        n_ref = len(reference)
        n_cur = len(current)
        n_total = n_ref + n_cur

        dof = len(all_categories) - 1
        if dof < 1:
            return 0.0, 1.0, 0

        chi2 = 0.0
        for cat in all_categories:
            observed_ref = ref_counts.get(cat, 0)
            observed_cur = cur_counts.get(cat, 0)
            total_cat = observed_ref + observed_cur

            # Expected counts under null hypothesis (same distribution)
            expected_ref = total_cat * n_ref / n_total
            expected_cur = total_cat * n_cur / n_total

            if expected_ref > 0:
                chi2 += (observed_ref - expected_ref) ** 2 / expected_ref
            if expected_cur > 0:
                chi2 += (observed_cur - expected_cur) ** 2 / expected_cur

        # Compute p-value using chi-squared distribution approximation
        p_value = self._chi2_p_value(chi2, dof)

        return chi2, p_value, dof

    def _chi2_p_value(self, chi2: float, dof: int) -> float:
        """Approximate p-value for chi-squared distribution.

        Uses the regularized incomplete gamma function approximation.
        """
        if chi2 <= 0:
            return 1.0
        if dof <= 0:
            return 1.0

        # Use Wilson-Hilferty approximation for large dof
        # For smaller dof, use series expansion
        return 1.0 - self._regularized_gamma(dof / 2.0, chi2 / 2.0)

    def _regularized_gamma(self, a: float, x: float) -> float:
        """Compute regularized lower incomplete gamma function P(a, x).

        Uses series expansion for convergence.
        """
        if x < 0:
            return 0.0
        if x == 0:
            return 0.0
        if x > a + 30:
            # Use complement for large x
            return 1.0 - self._upper_gamma_cf(a, x)

        # Series expansion: P(a,x) = e^{-x} * x^a * sum_{n=0}^{inf} x^n / (a*(a+1)*...*(a+n))
        ln_gamma_a = self._ln_gamma(a)

        total = 0.0
        term = 1.0 / a
        total = term
        for n in range(1, 300):
            term *= x / (a + n)
            total += term
            if abs(term) < abs(total) * 1e-12:
                break

        result = math.exp(-x + a * math.log(x) - ln_gamma_a) * total
        return max(0.0, min(1.0, result))

    def _upper_gamma_cf(self, a: float, x: float) -> float:
        """Upper incomplete gamma via continued fraction (Lentz's method)."""
        ln_gamma_a = self._ln_gamma(a)

        # Modified Lentz's method
        f = x - a + 1.0
        if abs(f) < 1e-30:
            f = 1e-30
        c = f
        d = 0.0
        result = 0.0

        # Simple approximation using first few terms
        # Q(a,x) = e^{-x} * x^a / gamma(a) * (1/(x-a+1+) 1/(x-a+3+) ...)
        # Use asymptotic expansion instead
        total = 1.0
        term = 1.0
        for n in range(1, 100):
            term *= (a - n) / x
            total += term
            if abs(term) < 1e-12:
                break

        result = math.exp(-x + (a - 1) * math.log(x) - ln_gamma_a) * total / x
        return max(0.0, min(1.0, result))

    def _ln_gamma(self, x: float) -> float:
        """Compute ln(gamma(x)) using Stirling's approximation with Lanczos coefficients."""
        if x <= 0:
            return 0.0

        # Lanczos approximation (g=7, n=9)
        coef = [
            0.99999999999980993,
            676.5203681218851,
            -1259.1392167224028,
            771.32342877765313,
            -176.61502916214059,
            12.507343278686905,
            -0.13857109526572012,
            9.9843695780195716e-6,
            1.5056327351493116e-7,
        ]

        if x < 0.5:
            # Reflection formula
            return math.log(math.pi / math.sin(math.pi * x)) - self._ln_gamma(1 - x)

        x -= 1
        a = coef[0]
        t = x + 7.5
        for i in range(1, 9):
            a += coef[i] / (x + i)

        return 0.5 * math.log(2 * math.pi) + (x + 0.5) * math.log(t) - t + math.log(a)

    def _psi_severity(self, psi: float) -> str:
        """Classify PSI value into severity levels."""
        if psi < self.psi_minor:
            return "none"
        elif psi < self.psi_moderate:
            return "minor"
        elif psi < self.psi_severe:
            return "moderate"
        else:
            return "severe"
