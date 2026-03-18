"""Central configuration for the phishing URL detector."""
from __future__ import annotations

from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
FRONTEND_DIR = BASE_DIR / "frontend"
STATIC_DIR = FRONTEND_DIR / "static"
TEMPLATES_DIR = FRONTEND_DIR / "templates"
MODEL_DIR = BASE_DIR / "model"
DATA_DIR = BASE_DIR / "data"
MODEL_PATH = MODEL_DIR / "phishing_detector.joblib"
BLACKLIST_PATH = MODEL_DIR / "blacklist.txt"
LOG_PATH = BASE_DIR / "backend" / "requests.log"
HOST = "127.0.0.1"
PORT = 8000
