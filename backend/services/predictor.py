"""Prediction service with model loading and rule-based fallback."""
from __future__ import annotations

import pickle
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from backend.config import BLACKLIST_PATH, MODEL_PATH
from backend.schemas import PredictionResponse
from model.feature_extractor import extract_url_features, validate_url


@dataclass
class PredictorService:
    model_path: Path = MODEL_PATH
    blacklist_path: Path = BLACKLIST_PATH
    _bundle: dict[str, object] | None = None

    def load_model(self) -> dict[str, object] | None:
        if self._bundle is not None:
            return self._bundle
        if not self.model_path.exists():
            return None
        try:
            with self.model_path.open("rb") as model_file:
                self._bundle = pickle.load(model_file)
        except Exception:
            self._bundle = None
        return self._bundle

    def load_blacklist(self) -> set[str]:
        if not self.blacklist_path.exists():
            return set()
        return {
            line.strip().lower()
            for line in self.blacklist_path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.strip().startswith("#")
        }

    def predict(self, raw_url: str) -> PredictionResponse:
        normalized_url = validate_url(raw_url)
        features = extract_url_features(normalized_url)
        domain = urlparse(normalized_url).netloc.lower()
        blacklist_match = domain in self.load_blacklist()
        reasons = self.build_reasons(features, blacklist_match)

        probability = self.rule_based_probability(features, blacklist_match)
        bundle = self.load_model()
        if bundle and bundle.get("model") is not None:
            try:
                model_probability = float(bundle["model"].predict_proba(features))
                probability = self.combine_probabilities(rule_probability=probability, model_probability=model_probability)
            except Exception:
                probability = self.rule_based_probability(features, blacklist_match)

        if blacklist_match:
            probability = max(probability, 0.98)

        probability = max(0.01, min(round(probability, 4), 0.99))
        prediction = "Scam" if probability >= 0.5 else "Safe"
        explanation = self.build_explanation(prediction, probability, reasons, features, blacklist_match)
        return PredictionResponse(
            url=normalized_url,
            prediction=prediction,
            probability=probability,
            explanation=explanation,
            blacklist_match=blacklist_match,
            reasons=reasons,
            features=features,
        )

    @staticmethod
    def combine_probabilities(rule_probability: float, model_probability: float) -> float:
        combined = (rule_probability * 0.45) + (model_probability * 0.55)
        return max(0.01, min(combined, 0.99))

    @staticmethod
    def rule_based_probability(features: dict[str, int | float | str], blacklist_match: bool) -> float:
        score = 0.06
        score += 0.34 if blacklist_match else 0.0
        score += 0.12 if int(features["has_https"]) == 0 else -0.05
        score += min(int(features["suspicious_keyword_count"]) * 0.14, 0.42)
        score += min(int(features["special_char_count"]) * 0.012, 0.16)
        score += min(int(features["digit_count"]) * 0.008, 0.08)
        score += min(int(features["subdomain_count"]) * 0.06, 0.18)
        score += 0.22 if int(features["contains_ip_like_host"]) == 1 else 0.0
        score += 0.14 if int(features["has_suspicious_tld"]) == 1 else 0.0
        score += 0.10 if int(features["simulated_domain_age_days"]) < 180 else -0.03
        score += 0.08 if int(features["url_length"]) > 75 else -0.02
        return max(0.01, min(score, 0.99))

    @staticmethod
    def build_reasons(features: dict[str, int | float | str], blacklist_match: bool) -> list[str]:
        reasons: list[str] = []
        if blacklist_match:
            reasons.append("Domain matched the local blacklist of known malicious hosts.")
        if int(features["has_https"]) == 0:
            reasons.append("The link does not use HTTPS, which lowers trust.")
        else:
            reasons.append("The link uses HTTPS, which is a positive trust signal.")
        if int(features["suspicious_keyword_count"]) > 0:
            reasons.append("The URL contains phishing-style keywords such as login, verify, secure, or account.")
        if int(features["special_char_count"]) >= 6:
            reasons.append("Heavy use of special characters can indicate obfuscation or tracking-heavy scam links.")
        if int(features["contains_ip_like_host"]) == 1:
            reasons.append("The host looks like an IP address instead of a standard domain name.")
        if int(features["has_suspicious_tld"]) == 1:
            reasons.append("The top-level domain is commonly seen in disposable or abusive URLs.")
        if int(features["simulated_domain_age_days"]) < 180:
            reasons.append("The simulated domain-age signal suggests a relatively new domain.")
        else:
            reasons.append("The simulated domain-age signal suggests the domain is not newly created.")
        if int(features["url_length"]) > 75:
            reasons.append("The URL is unusually long, which can hide deceptive paths.")
        if int(features["subdomain_count"]) >= 3:
            reasons.append("Multiple subdomains increase the chance of deceptive brand impersonation.")
        if int(features["digit_count"]) >= 5:
            reasons.append("A high number of digits can be a sign of generated or suspicious URLs.")
        return reasons[:5]

    @staticmethod
    def build_explanation(
        prediction: str,
        probability: float,
        reasons: list[str],
        features: dict[str, int | float | str],
        blacklist_match: bool,
    ) -> str:
        confidence_text = f"{prediction} with {probability * 100:.2f}% probability."
        if prediction == "Scam":
            summary = "The URL shows several phishing indicators"
            if blacklist_match:
                summary += ", including a blacklist match"
            if int(features["suspicious_keyword_count"]) > 0:
                summary += " and suspicious wording"
            summary += "."
        else:
            summary = "The URL looks comparatively safer because it shows more normal patterns than risky ones."
        return confidence_text + " " + summary + " " + " ".join(reasons)
