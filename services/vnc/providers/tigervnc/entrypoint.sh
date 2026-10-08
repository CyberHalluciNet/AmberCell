#!/bin/sh
set -eu

LOG_FIFO="${AMBER_VNC_LOG_FIFO:-/run/amber/log/vnc.fifo}"
mkdir -p "$(dirname "$LOG_FIFO")"
if [ ! -p "$LOG_FIFO" ]; then
  rm -f "$LOG_FIFO"
  mkfifo "$LOG_FIFO"
  chmod 666 "$LOG_FIFO" 2>/dev/null || true
fi

# Keep one writer attached for the process lifetime (collectors README contract).
{ tail -f /dev/null >"$LOG_FIFO" 2>/dev/null || true; } &

# Open VNC persona (SecurityTypes None): Debian has no vncpasswd binary and
# open-VNC is a real exposure pattern; RFB handshake is the evidence.
Xvnc :1 -geometry 1024x768 -depth 24 -rfbport 5900 -SecurityTypes None -localhost=0 -log '*:stderr:30' 2>&1 | while IFS= read -r line; do
  printf '%s\n' "$line" >>"$LOG_FIFO" 2>/dev/null || true
  printf '%s\n' "$line"
done
