#!/bin/sh
set -eu

JAIL="${AMBER_TELNET_JAIL:-/jail}"
RUN_DIR="${AMBER_TELNET_RUN_DIR:-/var/run/telnetd}"
PORT="${AMBER_TELNET_PORT:-23}"
BIND="${AMBER_TELNET_BIND:-0.0.0.0}"

mkdir -p "$JAIL/tmp" "$JAIL/home" "$RUN_DIR"
chmod 1777 "$JAIL/tmp" 2>/dev/null || true

# inetutils telnetd is inetd-style (stdin/stdout = client).
# tcpserver provides IPv4-only accept loop under cell containment.
exec tcpserver -RHl0 "$BIND" "$PORT" /usr/sbin/telnetd -h -E /usr/sbin/amber-login
