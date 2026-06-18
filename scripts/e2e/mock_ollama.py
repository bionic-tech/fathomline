"""Tiny deterministic stand-in for a local Ollama server, for the E2E harness only.

The Organize feature (ADR-021/022) calls a local Ollama at ``/api/chat`` with a JSON-schema
``format`` and expects ``{"message": {"content": "<schema-valid JSON>"}}``. A real LLM is
non-deterministic and may be absent on a CI box, so this mock plays the model's part: it parses the
prompt's ``[i] <relpath> ...`` listing and proposes a tidy ``target_dir`` per file by extension
(images/documents/audio/videos/archives/misc) — exactly the kind of grouping the real model is
asked for, but reproducible. It only ever emits in-root RELATIVE sub-folders; the server's
clamp_to_root remains the real safety boundary.

Run:  uv run python scripts/e2e/mock_ollama.py --port 11999
"""

from __future__ import annotations

import argparse
import json
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

_LINE = re.compile(r"^\[(\d+)\]\s+(\S+)")
_CATEGORY = {
    "jpg": "images", "jpeg": "images", "png": "images", "gif": "images", "heic": "images",
    "webp": "images", "tif": "images", "tiff": "images", "raw": "images",
    "pdf": "documents", "doc": "documents", "docx": "documents", "txt": "documents",
    "md": "documents", "rtf": "documents", "odt": "documents", "csv": "documents",
    "mp3": "audio", "flac": "audio", "wav": "audio", "aac": "audio", "ogg": "audio",
    "mp4": "videos", "mkv": "videos", "mov": "videos", "avi": "videos", "webm": "videos",
    "zip": "archives", "tar": "archives", "gz": "archives", "7z": "archives", "rar": "archives",
}


def _category(relpath: str) -> str:
    base = relpath.rsplit("/", 1)[-1]
    ext = base.rsplit(".", 1)[-1].lower() if "." in base else ""
    return _CATEGORY.get(ext, "misc")


def _proposal(user_content: str) -> dict:
    assignments = []
    for line in user_content.splitlines():
        m = _LINE.match(line.strip())
        if not m:
            continue
        idx, relpath = int(m.group(1)), m.group(2)
        assignments.append({"index": idx, "target_dir": _category(relpath), "new_name": ""})
    return {"assignments": assignments}


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *_a):  # quiet
        pass

    def _send(self, code: int, body: dict) -> None:
        raw = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self) -> None:  # /api/tags health probe etc.
        self._send(200, {"models": [{"name": "e2e-mock"}]})

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        try:
            req = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            self._send(400, {"error": "bad json"})
            return
        user = ""
        for msg in req.get("messages", []):
            if msg.get("role") == "user":
                user = msg.get("content", "")
        content = json.dumps(_proposal(user))
        self._send(200, {"model": req.get("model", "e2e-mock"), "message": {"role": "assistant", "content": content}})


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=11999)
    ap.add_argument("--host", default="127.0.0.1")
    args = ap.parse_args()
    srv = ThreadingHTTPServer((args.host, args.port), _Handler)
    print(f"mock-ollama listening on http://{args.host}:{args.port}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
