"""Application entry point.

Run locally with:
    python backend/app.py
"""
from __future__ import annotations

import json
import logging
import sys
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from logging.handlers import RotatingFileHandler
from pathlib import Path
from urllib.parse import urlparse

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.config import FRONTEND_DIR, HOST, LOG_PATH, PORT, STATIC_DIR, TEMPLATES_DIR
from backend.services.predictor import PredictorService

try:
    import uvicorn
    from fastapi import FastAPI, HTTPException, Request
    from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
    FASTAPI_AVAILABLE = True
except Exception:
    FASTAPI_AVAILABLE = False
    FastAPI = object
    Request = object
    HTTPException = Exception
    HTMLResponse = object
    FileResponse = object
    JSONResponse = object
    uvicorn = None

service = PredictorService()
logger = logging.getLogger("phishing_detector")
logger.setLevel(logging.INFO)
if not logger.handlers:
    handler = RotatingFileHandler(LOG_PATH, maxBytes=500_000, backupCount=3)
    handler.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s"))
    logger.addHandler(handler)


def _load_index_html() -> str:
    return (TEMPLATES_DIR / "index.html").read_text(encoding="utf-8")


def _json_bytes(payload: dict[str, object]) -> bytes:
    return json.dumps(payload, indent=2).encode("utf-8")


def _predict_payload(url: str) -> tuple[dict[str, object], int]:
    try:
        response = service.predict(url)
    except ValueError as exc:
        logger.warning("Invalid URL received: %s", url)
        return {"detail": str(exc)}, HTTPStatus.BAD_REQUEST

    logger.info("Prediction for %s => %s (%.2f%%)", response.url, response.prediction, response.probability * 100)
    return response.to_dict(), HTTPStatus.OK


if FASTAPI_AVAILABLE:
    app = FastAPI(title="AI-Powered Phishing & Scam URL Detection System", version="2.0.0")

    @app.get("/")
    async def index() -> HTMLResponse:
        return HTMLResponse(_load_index_html())

    @app.get("/static/{asset_path:path}")
    async def static_files(asset_path: str):
        target = (STATIC_DIR / asset_path).resolve()
        if not str(target).startswith(str(STATIC_DIR.resolve())) or not target.exists():
            raise HTTPException(status_code=404, detail="Asset not found")
        return FileResponse(target)

    @app.post("/api/predict")
    async def predict(request: Request):
        payload = await request.json()
        url = str(payload.get("url", ""))
        body, status = _predict_payload(url)
        if status != HTTPStatus.OK:
            raise HTTPException(status_code=status, detail=body["detail"])
        return JSONResponse(body)

else:
    app = None


class LocalRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/":
            body = _load_index_html().encode("utf-8")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if parsed.path.startswith("/static/"):
            target = (FRONTEND_DIR / parsed.path.lstrip("/")).resolve()
            allowed_root = FRONTEND_DIR.resolve()
            if not str(target).startswith(str(allowed_root)) or not target.exists() or not target.is_file():
                self.send_error(HTTPStatus.NOT_FOUND, "Asset not found")
                return
            content_type = "text/plain; charset=utf-8"
            if target.suffix == ".css":
                content_type = "text/css; charset=utf-8"
            elif target.suffix == ".js":
                content_type = "application/javascript; charset=utf-8"
            body = target.read_bytes()
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        self.send_error(HTTPStatus.NOT_FOUND, "Not found")

    def do_POST(self) -> None:
        if self.path != "/api/predict":
            self.send_error(HTTPStatus.NOT_FOUND, "Not found")
            return

        content_length = int(self.headers.get("Content-Length", "0"))
        raw_body = self.rfile.read(content_length).decode("utf-8")
        try:
            payload = json.loads(raw_body or "{}")
        except json.JSONDecodeError:
            self._send_json({"detail": "Request body must be valid JSON."}, HTTPStatus.BAD_REQUEST)
            return

        body, status = _predict_payload(str(payload.get("url", "")))
        self._send_json(body, status)

    def log_message(self, format: str, *args) -> None:
        logger.info("HTTP server | " + format, *args)

    def _send_json(self, payload: dict[str, object], status: int) -> None:
        body = _json_bytes(payload)
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main() -> None:
    if FASTAPI_AVAILABLE and uvicorn is not None:
        uvicorn.run(app, host=HOST, port=PORT)
    else:
        server = ThreadingHTTPServer((HOST, PORT), LocalRequestHandler)
        print(f"Serving app on http://{HOST}:{PORT} using the built-in fallback server")
        server.serve_forever()


if __name__ == "__main__":
    main()
