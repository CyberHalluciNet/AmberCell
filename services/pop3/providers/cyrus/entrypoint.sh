#!/bin/sh
set -eu

LOG_FIFO="${AMBER_POP3_LOG_FIFO:-/run/amber/log/pop3.fifo}"
mkdir -p "$(dirname "$LOG_FIFO")"
if [ ! -p "$LOG_FIFO" ]; then
  rm -f "$LOG_FIFO"
  mkfifo "$LOG_FIFO"
fi

mkdir -p /run/cyrus/socket /run/cyrus/proc /run/cyrus/lock \
  /var/lib/cyrus /var/spool/cyrus/mail
chown -R cyrus:mail /run/cyrus /var/lib/cyrus /var/spool/cyrus

# SASL lure users (same passwords as dovecot provider).
rm -f /etc/sasldb2
for pair in cyrus:cyrus exec:exec123 finance:finance123 hr:hr123 it:it123 canary:canary123; do
  u="${pair%%:*}"
  p="${pair#*:}"
  printf '%s' "$p" | saslpasswd2 -p -c "$u"
done
chown cyrus:mail /etc/sasldb2
chmod 640 /etc/sasldb2

# Debian cyrmaster may stay attached without a TTY; background it.
/usr/sbin/cyrmaster &
# Give master a moment to bind sockets.
sleep 0.5

i=0
while [ "$i" -lt 80 ]; do
  if [ -S /run/cyrus/socket/lmtp ]; then
    # Also wait for localhost IMAP (cyradm).
    if python3 -c 'import socket; s=socket.create_connection(("127.0.0.1",143),2); s.close()' 2>/dev/null; then
      break
    fi
  fi
  i=$((i + 1))
  sleep 0.1
done

export TERM="${TERM:-dumb}"
echo "amber-cyrus: creating mailboxes" >&2
expect <<'EOF'
set timeout 20
spawn cyradm --auth PLAIN -u cyrus localhost
expect "Password:"
send "cyrus\r"
expect ">"
foreach u {exec finance hr it canary} {
  send "cm user.$u\r"
  expect ">"
}
send "lm\r"
expect ">"
send "quit\r"
expect eof
EOF

echo "amber-cyrus: seeding mailboxes" >&2
python3 /usr/local/bin/seed_lmtp.py /opt/amber-seeds /run/cyrus/socket/lmtp
echo "amber-cyrus: ready" >&2

exec sleep infinity
