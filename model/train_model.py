"""Train the lightweight phishing detector and save a pre-trained model file."""
from __future__ import annotations

import csv
import pickle
import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from model.feature_extractor import extract_url_features, validate_url
from model.simple_model import SimpleURLModel

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_PATH = BASE_DIR / "data" / "url_dataset.csv"
MODEL_PATH = BASE_DIR / "model" / "phishing_detector.joblib"


def load_dataset() -> tuple[list[dict[str, int | float | str]], list[int]]:
    feature_rows: list[dict[str, int | float | str]] = []
    labels: list[int] = []
    with DATA_PATH.open("r", encoding="utf-8", newline="") as csv_file:
        reader = csv.DictReader(csv_file)
        for row in reader:
            normalized_url = validate_url(row["url"])
            feature_rows.append(extract_url_features(normalized_url))
            labels.append(int(row["label"]))
    return feature_rows, labels


def evaluate(model: SimpleURLModel, feature_rows: list[dict[str, int | float | str]], labels: list[int]) -> tuple[int, int]:
    correct = 0
    for feature_row, label in zip(feature_rows, labels):
        prediction = 1 if model.predict_proba(feature_row) >= 0.5 else 0
        correct += int(prediction == label)
    return correct, len(labels)


def train_model() -> Path:
    feature_rows, labels = load_dataset()
    model = SimpleURLModel().fit(feature_rows, labels)
    correct, total = evaluate(model, feature_rows, labels)

    payload = {
        "model_type": "SimpleURLModel",
        "model": model,
        "trained_samples": total,
    }
    with MODEL_PATH.open("wb") as model_file:
        pickle.dump(payload, model_file)

    accuracy = correct / total if total else 0.0
    print(f"Saved trained model to {MODEL_PATH}")
    print(f"Training-set accuracy: {accuracy:.2%} ({correct}/{total})")
    return MODEL_PATH


if __name__ == "__main__":
    train_model()
