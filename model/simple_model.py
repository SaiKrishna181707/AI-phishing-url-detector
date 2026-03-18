"""A lightweight, dependency-free phishing classifier used for demo training."""
from __future__ import annotations

from dataclasses import dataclass, field
from math import exp

NUMERIC_FEATURES = [
    "url_length",
    "has_https",
    "special_char_count",
    "digit_count",
    "subdomain_count",
    "suspicious_keyword_count",
    "contains_ip_like_host",
    "simulated_domain_age_days",
    "has_suspicious_tld",
]


@dataclass
class SimpleURLModel:
    """Small probability model trained from feature averages."""

    safe_means: dict[str, float] = field(default_factory=dict)
    scam_means: dict[str, float] = field(default_factory=dict)
    safe_domains: set[str] = field(default_factory=set)
    scam_domains: set[str] = field(default_factory=set)

    def fit(self, feature_rows: list[dict[str, int | float | str]], labels: list[int]) -> "SimpleURLModel":
        safe_rows = [row for row, label in zip(feature_rows, labels) if label == 0]
        scam_rows = [row for row, label in zip(feature_rows, labels) if label == 1]
        if not safe_rows or not scam_rows:
            raise ValueError("Training requires both safe and scam samples.")

        self.safe_means = {
            feature: sum(float(row[feature]) for row in safe_rows) / len(safe_rows)
            for feature in NUMERIC_FEATURES
        }
        self.scam_means = {
            feature: sum(float(row[feature]) for row in scam_rows) / len(scam_rows)
            for feature in NUMERIC_FEATURES
        }
        self.safe_domains = {str(row["domain"]) for row in safe_rows}
        self.scam_domains = {str(row["domain"]) for row in scam_rows}
        return self

    def predict_proba(self, feature_row: dict[str, int | float | str]) -> float:
        score = 0.0
        for feature in NUMERIC_FEATURES:
            value = float(feature_row[feature])
            safe_mean = self.safe_means.get(feature, 0.0)
            scam_mean = self.scam_means.get(feature, 0.0)
            weight = abs(scam_mean - safe_mean) or 1.0
            midpoint = (safe_mean + scam_mean) / 2.0
            direction = 1.0 if scam_mean >= safe_mean else -1.0
            score += direction * ((value - midpoint) / weight)

        domain = str(feature_row.get("domain", ""))
        if domain in self.scam_domains:
            score += 1.35
        elif domain in self.safe_domains:
            score -= 1.15

        return 1.0 / (1.0 + exp(-score))
