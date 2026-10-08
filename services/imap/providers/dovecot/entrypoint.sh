#!/bin/sh
set -eu

LOG_FIFO="${AMBER_IMAP_LOG_FIFO:-/run/amber/log/imap.fifo}"
mkdir -p "$(dirname "$LOG_FIFO")"
if [ ! -p "$LOG_FIFO" ]; then
  rm -f "$LOG_FIFO"
  mkfifo "$LOG_FIFO"
  chmod 666 "$LOG_FIFO" 2>/dev/null || true
fi
{ tail -f /dev/null >"$LOG_FIFO" 2>/dev/null || true; } &

# Seed inboxes on the tmpfs; dovecot indexes are per-session (rebuild resets).
for u in hr finance admin support; do
  mkdir -p "/tmp/mail/$u"
  printf 'From ambercell-lure@ambercell.lab\nSubject: Welcome\n\nSeeded mailbox for %s.\n' "$u" > "/tmp/mail/$u/inbox"
done

dovecot -F 2>&1 | while IFS= read -r line; do
  printf '%s\n' "$line" >>"$LOG_FIFO" 2>/dev/null || true
  printf '%s\n' "$line"
done
