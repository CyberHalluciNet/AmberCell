#!/usr/bin/env python3
"""Fake kubelet HTTP API — capture exec/pod abuse; no real cluster.

Profiles (AMBER_KUBELET_TRAP_PROFILE):
  default  — generic kubelet lure
  unauth   — openly exposed unauthenticated kubelet surface (extra probes)
  exec     — exec/attach-focused responses (richer command capture)
"""

from __future__ import annotations

import json
import os
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

LISTEN = os.environ.get("AMBER_KUBELET_LISTEN", "0.0.0.0:10250")
LOG_FIFO = os.environ.get("AMBER_KUBELET_LOG_FIFO", "/run/amber/log/kubelet.fifo")
PROVIDER_ID = os.environ.get("AMBER_KUBELET_PROVIDER", "trap")
PROFILE = os.environ.get("AMBER_KUBELET_TRAP_PROFILE", "default").strip().lower()

_fifo_lock = threading.Lock()


def _emit(event: str, src_ip: str, **details: object) -> None:
    payload = {
        "event": event,
        "provider_id": PROVIDER_ID,
        "trap_profile": PROFILE,
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


class Handler(BaseHTTPRequestHandler):
    @property
    def server_version(self) -> str:  # type: ignore[override]
        if PROFILE == "unauth":
            return "kubelet/v1.27-trap-unauth"
        if PROFILE == "exec":
            return "kubelet/v1.28-trap-exec"
        return "kubelet/v1.28-trap"

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
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        src = self.client_address[0]
        # Never challenge for credentials — honeypot always "open".
        if path in ("/healthz", "/healthz/"):
            _emit("kubelet.health_probe", src, path=path)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")
            return
        if PROFILE == "unauth" and path in ("/metrics", "/metrics/cadvisor", "/stats/summary"):
            _emit("kubelet.metrics_probe", src, path=path)
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"# TYPE kubelet_running_pods gauge\nkubelet_running_pods 0\n")
            return
        if PROFILE == "unauth" and path in ("/runningpods/", "/runningpods"):
            _emit("kubelet.runningpods_probe", src, path=path)
            self._respond(200, {"kind": "PodList", "items": []})
            return
        if path.startswith("/pods") or path == "/api/v1/nodes":
            _emit("kubelet.list_probe", src, path=path)
            self._respond(200, {"items": [], "kind": "PodList"})
            return
        if PROFILE == "exec" and ("/exec/" in path or path.endswith("/exec")):
            q = parse_qs(parsed.query)
            _emit(
                "kubelet.exec_get",
                src,
                path=path,
                command=q.get("command") or q.get("cmd"),
                container=q.get("container", [None])[0],
            )
            self._respond(200, {"url": f"wss://trap/exec/{uuid.uuid4().hex[:8]}", "status": "prepared"})
            return
        _emit("kubelet.request", src, method="GET", path=path)
        self._respond(404, {"message": "kubelet trap: not found"})

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        src = self.client_address[0]
        body = self._read_json()

        if "exec" in path or path.endswith("/exec"):
            cmd = body.get("command") or body.get("Cmd")
            if PROFILE == "exec":
                # Prefer query-string command arrays used by kubectl exec.
                q = parse_qs(parsed.query)
                if not cmd:
                    cmd = q.get("command") or q.get("cmd")
            _emit(
                "kubelet.exec",
                src,
                path=path,
                command=cmd,
                stdin=body.get("stdin"),
                tty=body.get("tty"),
            )
            if PROFILE == "exec":
                self._respond(
                    200,
                    {
                        "url": f"wss://trap/exec/{uuid.uuid4().hex[:8]}",
                        "id": uuid.uuid4().hex[:12],
                        "status": "exec-session-stub",
                    },
                )
            else:
                self._respond(200, {"url": f"wss://trap/exec/{uuid.uuid4().hex[:8]}"})
            return

        if "run" in path or "attach" in path:
            _emit("kubelet.attach", src, path=path, body_keys=sorted(body.keys())[:16])
            if PROFILE == "exec":
                self._respond(200, {"url": f"wss://trap/attach/{uuid.uuid4().hex[:8]}"})
            else:
                self._respond(101, {})
            return

        if path.startswith("/pods") or "pod" in path.lower():
            if PROFILE == "exec":
                # Exec-focused profile still records pod specs but returns a soft deny.
                spec = body.get("spec") or body
                _emit(
                    "kubelet.pod_spec_ignored",
                    src,
                    path=path,
                    containers=[c.get("name") for c in (spec.get("containers") or []) if isinstance(c, dict)],
                )
                self._respond(403, {"message": "trap-exec: use exec/attach paths"})
                return
            spec = body.get("spec") or body
            _emit(
                "kubelet.pod_spec",
                src,
                path=path,
                containers=[c.get("name") for c in (spec.get("containers") or []) if isinstance(c, dict)],
                host_network=spec.get("hostNetwork"),
                host_pid=spec.get("hostPID"),
            )
            self._respond(201, {"metadata": {"name": f"trap-{uuid.uuid4().hex[:6]}"}})
            return

        _emit("kubelet.request", src, method="POST", path=path)
        self._respond(404, {"message": "kubelet trap: not found"})


def main() -> None:
    host, _, port_s = LISTEN.partition(":")
    port = int(port_s or "10250")
    httpd = ThreadingHTTPServer((host, port), Handler)
    print(f"kubelet trap ({PROFILE}) listening on {host}:{port}", flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
