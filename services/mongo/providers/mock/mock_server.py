#!/usr/bin/env python3
"""Minimal MongoDB wire-protocol lure — capture connection intents; not a real DB."""

from __future__ import annotations

import json
import os
import socket
import threading

LISTEN = os.environ.get("AMBER_MONGO_LISTEN", "0.0.0.0:27017")
LOG_FIFO = os.environ.get("AMBER_MONGO_LOG_FIFO", "/run/amber/log/mongo.fifo")
PROVIDER_ID = os.environ.get("AMBER_MONGO_PROVIDER", "mock")

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


def _handle(conn: socket.socket, addr: tuple) -> None:
    src = addr[0]
    _emit("mongo.connect", src)
    try:
        # Read one OP_MSG / legacy header if present; always close after lure banner bytes.
        conn.settimeout(5.0)
        data = conn.recv(1024)
        _emit("mongo.request", src, nbytes=len(data or b""), head=(data or b"")[:64].hex())
        # Minimal isMaster-ish BSON-ish payload is complex; send empty and close.
        # Attackers probing Mongo still generate connect/request evidence.
        conn.sendall(b"")
    except OSError:
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass
        _emit("mongo.disconnect", src)


def main() -> None:
    host, _, port_s = LISTEN.partition(":")
    port = int(port_s or "27017")
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(64)
    print(f"mongo mock listening on {host}:{port}", flush=True)
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=_handle, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    main()
