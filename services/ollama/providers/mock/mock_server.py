#!/usr/bin/env python3
"""Ollama-compatible mock — canned responses, no model downloads."""

from __future__ import annotations

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

LISTEN = os.environ.get("AMBER_OLLAMA_LISTEN", "0.0.0.0:11434")
LOG_FIFO = os.environ.get("AMBER_OLLAMA_LOG_FIFO", "/run/amber/log/ollama.fifo")
PROVIDER_ID = os.environ.get("AMBER_OLLAMA_PROVIDER", "mock")
MODEL_STUB = os.environ.get("AMBER_OLLAMA_STUB_MODEL", "tiny-stub:latest")

_fifo_lock = threading.Lock()


def _emit(event: str, src_ip: str, **details: object) -> None:
    payload = {"event": event, "provider_id": PROVIDER_ID, "src_ip": src_ip, **details}
    line = "AMBER_JSON:" + json.dumps(payload, separators=(",", ":"))
    with _fifo_lock:
        try:
            with open(LOG_FIFO, "w", encoding="utf-8") as fh:
                fh.write(line + "\n")
                fh.flush()
        except OSError:
            pass


class Handler(BaseHTTPRequestHandler):
    server_version = "ollama-mock/0.1"

    def log_message(self, fmt: str, *args: object) -> None:
        return

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return {}
        raw = self.rfile.read(min(length, 2_097_152))
        try:
            return json.loads(raw.decode("utf-8", errors="replace"))
        except json.JSONDecodeError:
            return {"_raw": raw[:8192].decode("utf-8", errors="replace")}

    def _respond(self, code: int, body: object, *, ndjson: bool = False) -> None:
        if ndjson:
            lines = body if isinstance(body, list) else [body]
            data = b"".join(json.dumps(x).encode("utf-8") + b"\n" for x in lines)
            self.send_response(code)
            self.send_header("Content-Type", "application/x-ndjson")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        data = json.dumps(body).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        src = self.client_address[0]
        if path in ("/", "/api/tags"):
            _emit("ollama.tags", src, path=path)
            self._respond(
                200,
                {"models": [{"name": MODEL_STUB, "size": 1024, "digest": "stub0001"}]},
            )
            return
        _emit("ollama.request", src, method="GET", path=path)
        self._respond(404, {"error": "not found"})

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        src = self.client_address[0]
        body = self._read_json()

        if path == "/api/pull" or path.endswith("/pull"):
            model = body.get("name") or body.get("model") or MODEL_STUB
            _emit("ollama.pull", src, model=str(model)[:256], insecure=body.get("insecure"))
            self._respond(
                200,
                [
                    {"status": "pulling manifest"},
                    {"status": "success", "digest": "stub0001"},
                ],
                ndjson=True,
            )
            return

        if path in ("/api/generate", "/api/chat") or path.startswith("/v1/"):
            prompt = body.get("prompt") or body.get("input") or ""
            messages = body.get("messages") or []
            tools = body.get("tools") or body.get("tool_choice")
            _emit(
                "ollama.prompt",
                src,
                path=path,
                prompt=str(prompt)[:4096],
                message_count=len(messages) if isinstance(messages, list) else 0,
                has_tools=bool(tools),
                model=body.get("model") or MODEL_STUB,
            )
            if tools:
                _emit("ollama.tool_invoke", src, path=path, tools=str(tools)[:2048])
            self._respond(
                200,
                {
                    "model": body.get("model") or MODEL_STUB,
                    "response": "stub-response (no GPU)",
                    "done": True,
                },
            )
            return

        _emit("ollama.request", src, method="POST", path=path, keys=sorted(body.keys())[:20])
        self._respond(404, {"error": "not found"})


def main() -> None:
    host, _, port_s = LISTEN.partition(":")
    port = int(port_s or "11434")
    httpd = ThreadingHTTPServer((host, port), Handler)
    print(f"ollama mock listening on {host}:{port}", flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
