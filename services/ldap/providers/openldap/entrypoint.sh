#!/bin/sh
set -eu

LOG_FIFO="${AMBER_LDAP_LOG_FIFO:-/run/amber/log/ldap.fifo}"
mkdir -p "$(dirname "$LOG_FIFO")"
if [ ! -p "$LOG_FIFO" ]; then
  rm -f "$LOG_FIFO"
  mkfifo "$LOG_FIFO"
  chmod 666 "$LOG_FIFO" 2>/dev/null || true
fi
{ tail -f /dev/null >"$LOG_FIFO" 2>/dev/null || true; } &

# mdb dir is a tmpfs (/tmp); the seed is re-loaded on every start so rebuilds
# reset the persona (seed_manifest covers the LDIF).
rm -rf /tmp/db && mkdir -p /tmp/db
slapadd -q -f /etc/ldap/slapd.conf -l /etc/ldap/seed/ambercell.ldif

exec slapd -d stats -f /etc/ldap/slapd.conf -h "ldap://:389" 2>&1 | while IFS= read -r line; do
  printf '%s
' "$line" >>"$LOG_FIFO" 2>/dev/null || true
  printf '%s
' "$line"
done
