"""Feature extraction and URL validation utilities."""
from __future__ import annotations

from hashlib import sha256
from urllib.parse import urlparse

SUSPICIOUS_KEYWORDS = {
    "login", "verify", "update", "secure", "account", "bank", "wallet",
    "free", "bonus", "signin", "confirm", "reset", "urgent", "gift", "invoice",
}
SUSPICIOUS_TLDS = {"zip", "xyz", "top", "click", "gq", "work", "support", "live"}
SPECIAL_CHARACTERS = set("@-_?=&%./")


def validate_url(url: str) -> str:
    candidate = (url or "").strip()
    if not candidate:
        raise ValueError("Please enter a URL to analyze.")
    if not candidate.startswith(("http://", "https://")):
        candidate = f"http://{candidate}"
    parsed = urlparse(candidate)
    if not parsed.netloc or "." not in parsed.netloc:
        raise ValueError("Please enter a valid URL, for example https://example.com.")
    return candidate


def simulate_domain_age_days(domain: str) -> int:
    digest = sha256(domain.encode("utf-8")).hexdigest()
    return 30 + (int(digest[:8], 16) % 1825)


def extract_url_features(url: str) -> dict[str, int | float | str]:
    parsed = urlparse(url)
    normalized_url = url.lower()
    domain = parsed.netloc.lower()
    tld = domain.rsplit(".", 1)[-1] if "." in domain else domain

    return {
        "url_length": len(url),
        "has_https": int(parsed.scheme == "https"),
        "special_char_count": sum(char in SPECIAL_CHARACTERS for char in url),
        "digit_count": sum(char.isdigit() for char in url),
        "subdomain_count": max(domain.count(".") - 1, 0),
        "suspicious_keyword_count": sum(keyword in normalized_url for keyword in SUSPICIOUS_KEYWORDS),
        "contains_ip_like_host": int(all(part.isdigit() for part in domain.replace(":", ".").split(".") if part)),
        "simulated_domain_age_days": simulate_domain_age_days(domain),
        "has_suspicious_tld": int(tld in SUSPICIOUS_TLDS),
        "domain": domain,
    }


def explain_features(features: dict[str, int | float | str], blacklist_match: bool) -> list[str]:
    reasons: list[str] = []
    if blacklist_match:
        reasons.append("Domain appears in the local blacklist.")
    if int(features["has_https"]) == 0:
        reasons.append("The link does not use HTTPS.")
    if int(features["suspicious_keyword_count"]) > 0:
        reasons.append("The URL contains suspicious phishing-style keywords.")
    if int(features["special_char_count"]) >= 6:
        reasons.append("The URL uses many special characters, which can signal obfuscation.")
    if int(features["contains_ip_like_host"]) == 1:
        reasons.append("The host looks like an IP address instead of a normal domain.")
    if int(features["has_suspicious_tld"]) == 1:
        reasons.append("The top-level domain is commonly abused in scam links.")
    if int(features["simulated_domain_age_days"]) < 180:
        reasons.append("The domain appears relatively new in the simulated age signal.")
    if int(features["url_length"]) > 75:
        reasons.append("The URL is unusually long.")
    if not reasons:
        reasons.append("The URL shows mostly normal patterns such as HTTPS usage and low obfuscation.")
    return reasons
