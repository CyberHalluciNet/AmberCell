#!/bin/sh
set -eu

LOG_FIFO="${AMBER_POP3_LOG_FIFO:-/run/amber/log/pop3.fifo}"
mkdir -p "$(dirname "$LOG_FIFO")"
if [ ! -p "$LOG_FIFO" ]; then
  rm -f "$LOG_FIFO"
  mkfifo "$LOG_FIFO"
fi

mkdir -p /run/courier/authdaemon
chown -R daemon:daemon /run/courier 2>/dev/null || true

# Seed Maildirs from mbox files (drop From_ line).
for u in exec finance hr it canary; do
  seed="/opt/amber-seeds/${u}.mbox"
  md="/home/$u/Maildir"
  mkdir -p "$md/new" "$md/cur" "$md/tmp"
  if [ -f "$seed" ]; then
    # Unique Maildir filename.
    dest="$md/new/amber-seed.${u}.$$"
    tail -n +2 "$seed" > "$dest"
  fi
  chown -R "$u:$u" "/home/$u"
done

/usr/sbin/authdaemond start

# Foreground couriertcpd (same args as /usr/lib/courier/pop3d start).
exec /usr/sbin/couriertcpd \
  -address=0 \
  -maxprocs=40 \
  -maxperip=4 \
  -nodnslookup \
  -noidentlookup \
  110 \
  /usr/lib/courier/courier/courierpop3login \
  /usr/lib/courier/courier/courierpop3d \
  Maildir
