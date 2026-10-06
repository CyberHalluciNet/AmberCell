#!/usr/bin/env python3
"""Docker Engine API trap — capture intents only; never touches real dockerd."""

from __future__ import annotations

import json
import os
import re
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

LISTEN = os.environ.get("AMBER_DOCKERAPI_LISTEN", "0.0.0.0:2375")
LOG_FIFO = os.environ.get("AMBER_DOCKERAPI_LOG_FIFO", "/run/amber/log/dockerapi.fifo")
PROVIDER_ID = os.environ.get("AMBER_DOCKERAPI_PROVIDER", "trap")

_fifo_lock = threading.Lock()


def _emit(event: str, src_ip: str, **details: object) -> None:
    payload = {
        "event": event,
        "provider_id": PROVIDER_ID,
        "src_ip": src_ip,
        **details,
    }
    line = "AMBER_JSON:" + json.dumps(payload, separators=(",", ":"))
    with _fifo_lock:
        try:
            with open(LOG_FIFO, "w", encoding="utf-8") as fh:
                fh.write(line + "\n")
                fh.flush()
        except OSError:
            pass


def _scan_host_abuse(body: dict) -> list[str]:
    flags: list[str] = []
    hc = body.get("HostConfig") or {}
    if hc.get("Privileged") is True:
        flags.append("privileged")
    binds = hc.get("Binds") or []
    for b in binds:
        if isinstance(b, str) and (b.startswith("/:") or b.startswith("/:/") or re.match(r"^/[^:]*:", b)):
            if b.split(":")[0] in ("/", "/etc", "/var/run", "/root", "/proc", "/sys"):
                flags.append("host_bind")
    for m in hc.get("Mounts") or []:
        if isinstance(m, dict) and m.get("Source") == "/":
            flags.append("root_mount")
    return flags


class Handler(BaseHTTPRequestHandler):
    server_version = "Docker/24.0.9 (trap)"
    sys_version = ""

    def log_message(self, fmt: str, *args: object) -> None:
        return

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return {}
        raw = self.rfile.read(min(length, 1_048_576))
        try:
            return json.loads(raw.decode("utf-8", errors="replace"))
        except json.JSONDecodeError:
            return {"_raw": raw[:4096].decode("utf-8", errors="replace")}

    def _respond(self, code: int, body: object) -> None:
        data = json.dumps(body).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Server", self.server_version)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        src = self.client_address[0]
        if path in ("/version", "/v1.41/version", "/v1.42/version"):
            _emit("dockerapi.version_probe", src, path=path)
            self._respond(
                200,
                {
                    "Platform": {"Name": "Docker Engine - Community"},
                    "Version": "24.0.9",
                    "ApiVersion": "1.43",
                    "MinAPIVersion": "1.12",
                },
            )
            return
        if path == "/info" or path.endswith("/info"):
            _emit("dockerapi.info_probe", src, path=path)
            self._respond(200, {"ID": "trap-mock", "Containers": 0, "Images": 0})
            return
        _emit("dockerapi.request", src, method="GET", path=path)
        self._respond(404, {"message": "Not found (trap)"})

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        src = self.client_address[0]
        body = self._read_json()

        if "images/create" in path or path.endswith("/pull"):
            image = body.get("fromImage") or self.headers.get("X-Registry-Auth") or "unknown"
            _emit(
                "dockerapi.pull",
                src,
                path=path,
                image=str(image)[:256],
                query=self.path,
            )
            self._respond(200, {"status": "Pulling from trap registry (no real pull)"})
            return

        if "containers/create" in path or path.endswith("/create"):
            abuse = _scan_host_abuse(body)
            ev = "dockerapi.container_create"
            if abuse:
                ev = "dockerapi.container_create_critical"
            _emit(
                ev,
                src,
                path=path,
                image=(body.get("Image") or body.get("Config", {}).get("Image") or "")[:256],
                abuse_flags=abuse,
                host_config_keys=sorted((body.get("HostConfig") or {}).keys()),
            )
            cid = uuid.uuid4().hex[:12]
            self._respond(201, {"Id": cid, "Warnings": []})
            return

        if "/exec" in path:
            _emit(
                "dockerapi.exec",
                src,
                path=path,
                cmd=body.get("Cmd"),
                attach=body.get("AttachStdout"),
            )
            self._respond(201, {"Id": uuid.uuid4().hex[:12]})
            return

        if "/start" in path:
            _emit("dockerapi.start", src, path=path)
            self._respond(204, {})
            return

        _emit("dockerapi.request", src, method="POST", path=path, body_keys=sorted(body.keys())[:20])
        self._respond(404, {"message": "Not found (trap)"})


def main() -> None:
    host, _, port_s = LISTEN.partition(":")
    port = int(port_s or "2375")
    httpd = ThreadingHTTPServer((host, port), Handler)
    print(f"dockerapi trap listening on {host}:{port}", flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
