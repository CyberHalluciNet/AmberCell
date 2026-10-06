#!/bin/sh
set -eu

# Runtime paths for read_only rootfs (see README tmpfs table).
JAIL="${AMBER_TELNET_JAIL:-/jail}"
RUN_DIR="${AMBER_TELNET_RUN_DIR:-/var/run/telnetd}"
PORT="${AMBER_TELNET_PORT:-23}"
BIND="${AMBER_TELNET_BIND:-0.0.0.0}"

mkdir -p "$JAIL/tmp" "$JAIL/home" "$RUN_DIR"
chmod 1777 "$JAIL/tmp" 2>/dev/null || true

# Must invoke /usr/sbin/telnetd (busybox-extras), not `busybox telnetd`
# (main busybox binary lacks the telnetd applet).
exec /usr/sbin/telnetd -F -K -l /usr/sbin/amber-login -p "$PORT" -b "$BIND"
