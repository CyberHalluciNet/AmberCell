#!/usr/bin/env python3
"""Docker Engine API trap — capture intents only; never touches real dockerd.

Profiles (AMBER_DOCKERAPI_TRAP_PROFILE):
  default  — generic Engine API lure
  v1.41    — advertise API 1.41 / older Engine banner
  swarm    — fake Swarm manager surface (/swarm, /services, /nodes)
"""

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
PROFILE = os.environ.get("AMBER_DOCKERAPI_TRAP_PROFILE", "default").strip().lower()

_fifo_lock = threading.Lock()

_VERSION = {
    "default": {
        "server": "Docker/24.0.9 (trap)",
        "Version": "24.0.9",
        "ApiVersion": "1.43",
        "MinAPIVersion": "1.12",
    },
    "v1.41": {
        "server": "Docker/20.10.24 (trap-v1.41)",
        "Version": "20.10.24",
        "ApiVersion": "1.41",
        "MinAPIVersion": "1.12",
    },
    "swarm": {
        "server": "Docker/24.0.9 (trap-swarm)",
        "Version": "24.0.9",
        "ApiVersion": "1.43",
        "MinAPIVersion": "1.12",
    },
}


def _profile_meta() -> dict:
    return _VERSION.get(PROFILE, _VERSION["default"])


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


def _strip_api_prefix(path: str) -> str:
    # /v1.41/containers/json → /containers/json
    m = re.match(r"^/v1\.\d+(/.*)?$", path)
    if m:
        return m.group(1) or "/"
    return path


class Handler(BaseHTTPRequestHandler):
    sys_version = ""

    @property
    def server_version(self) -> str:  # type: ignore[override]
        return _profile_meta()["server"]

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

    def _handle_swarm_get(self, path: str, src: str) -> bool:
        if PROFILE != "swarm":
            return False
        norm = _strip_api_prefix(path)
        if norm in ("/swarm", "/swarm/"):
            _emit("dockerapi.swarm_probe", src, path=path)
            self._respond(
                200,
                {
                    "ID": "trapswarm1",
                    "Version": {"Index": 1},
                    "JoinTokens": {"Worker": "SWMTKN-trap-worker", "Manager": "SWMTKN-trap-manager"},
                },
            )
            return True
        if norm.startswith("/nodes"):
            _emit("dockerapi.swarm_nodes", src, path=path)
            self._respond(
                200,
                [
                    {
                        "ID": "node-trap-1",
                        "Description": {"Hostname": "ambercell-swarm-node"},
                        "Status": {"State": "ready"},
                        "Spec": {"Role": "manager"},
                    }
                ],
            )
            return True
        if norm.startswith("/services"):
            _emit("dockerapi.swarm_services", src, path=path)
            self._respond(200, [])
            return True
        if norm.startswith("/tasks"):
            _emit("dockerapi.swarm_tasks", src, path=path)
            self._respond(200, [])
            return True
        return False

    def _handle_swarm_post(self, path: str, src: str, body: dict) -> bool:
        if PROFILE != "swarm":
            return False
        norm = _strip_api_prefix(path)
        if norm.startswith("/services/create") or norm.endswith("/services/create"):
            _emit(
                "dockerapi.swarm_service_create",
                src,
                path=path,
                name=(body.get("Name") or "")[:128],
                image=((body.get("TaskTemplate") or {}).get("ContainerSpec") or {}).get("Image", "")[:256],
            )
            self._respond(201, {"ID": uuid.uuid4().hex[:12], "Warning": []})
            return True
        if "/swarm/join" in norm or norm.endswith("/swarm/init"):
            _emit("dockerapi.swarm_join_or_init", src, path=path, body_keys=sorted(body.keys())[:20])
            self._respond(200, {"NodeID": "node-trap-join"})
            return True
        return False

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        src = self.client_address[0]
        if self._handle_swarm_get(path, src):
            return
        meta = _profile_meta()
        if path in ("/version", "/v1.41/version", "/v1.42/version", "/v1.43/version") or path.endswith(
            "/version"
        ):
            _emit("dockerapi.version_probe", src, path=path)
            self._respond(
                200,
                {
                    "Platform": {"Name": "Docker Engine - Community"},
                    "Version": meta["Version"],
                    "ApiVersion": meta["ApiVersion"],
                    "MinAPIVersion": meta["MinAPIVersion"],
                },
            )
            return
        if path == "/info" or path.endswith("/info"):
            _emit("dockerapi.info_probe", src, path=path)
            info = {"ID": "trap-mock", "Containers": 0, "Images": 0, "ServerVersion": meta["Version"]}
            if PROFILE == "swarm":
                info["Swarm"] = {"LocalNodeState": "active", "ControlAvailable": True, "Nodes": 1}
            self._respond(200, info)
            return
        _emit("dockerapi.request", src, method="GET", path=path)
        self._respond(404, {"message": "Not found (trap)"})

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        src = self.client_address[0]
        body = self._read_json()
        if self._handle_swarm_post(path, src, body):
            return

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
    print(f"dockerapi trap ({PROFILE}) listening on {host}:{port}", flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
