#!/bin/sh
set -eu

LOG_FIFO="${AMBER_SMTP_LOG_FIFO:-/run/amber/log/smtp.fifo}"
mkdir -p "$(dirname "$LOG_FIFO")"
if [ ! -p "$LOG_FIFO" ]; then
  rm -f "$LOG_FIFO"
  mkfifo "$LOG_FIFO"
fi

for u in hr finance admin support; do
  touch "/var/mail/$u"
  chown "$u:mail" "/var/mail/$u" 2>/dev/null || chown "$u" "/var/mail/$u" 2>/dev/null || true
done

mkdir -p /var/spool/postfix/pid /var/spool/postfix/public /var/spool/postfix/maildrop \
  /var/spool/postfix/incoming /var/spool/postfix/active /var/spool/postfix/deferred \
  /var/spool/postfix/bounce /var/spool/postfix/corrupt /var/spool/postfix/hold \
  /var/spool/postfix/trace /var/spool/postfix/defer /var/spool/postfix/flush \
  /var/spool/postfix/private /var/lib/postfix

postfix set-permissions
postfix upgrade-configuration
postfix check
postfix start
# Keep *-hi alive while master runs (Tini reaps zombies; master is daemonized).
exec sleep infinity
