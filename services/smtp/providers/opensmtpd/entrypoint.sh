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

# OpenSMTPD portable spool layout (root owns tree; smtpq owns purge/queue).
mkdir -p /var/spool/smtpd
chmod 711 /var/spool/smtpd
chown root:root /var/spool/smtpd
for d in corrupt incoming temporary; do
  mkdir -p "/var/spool/smtpd/$d"
  chown root:root "/var/spool/smtpd/$d"
  chmod 700 "/var/spool/smtpd/$d"
done
mkdir -p /var/spool/smtpd/offline
chown root:smtpq /var/spool/smtpd/offline
chmod 770 /var/spool/smtpd/offline
for d in purge queue; do
  mkdir -p "/var/spool/smtpd/$d"
  chown smtpq:root "/var/spool/smtpd/$d"
  chmod 700 "/var/spool/smtpd/$d"
done

smtpd -n -f /etc/smtpd/smtpd.conf
exec smtpd -d -f /etc/smtpd/smtpd.conf
