#!/bin/bash
set -euo pipefail

LOG_FIFO="${AMBER_SMB_LOG_FIFO:-/run/amber/log/smb.fifo}"
mkdir -p "$(dirname "$LOG_FIFO")" /shares/public /shares/admin /var/log/samba
echo 'canary doc' >/shares/public/README_CANARY.txt
(echo 'Welcome1'; echo 'Welcome1') | smbpasswd -a -s admin 2>/dev/null || true
smbpasswd -e admin 2>/dev/null || true

if [ ! -p "$LOG_FIFO" ]; then
  rm -f "$LOG_FIFO"
  mkfifo "$LOG_FIFO"
  chmod 666 "$LOG_FIFO" 2>/dev/null || true
fi

exec smbd -F -S 2>&1 | while IFS= read -r line; do
  printf '%s\n' "$line" >>"$LOG_FIFO" 2>/dev/null || true
  printf '%s\n' "$line"
done
