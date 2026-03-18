"""Shared request and response schemas."""
from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass
class URLRequest:
    url: str


@dataclass
class PredictionResponse:
    url: str
    prediction: str
    probability: float
    explanation: str
    blacklist_match: bool
    reasons: list[str]
    features: dict[str, int | float | str]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)
