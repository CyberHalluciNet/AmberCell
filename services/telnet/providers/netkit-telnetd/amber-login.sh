#!/bin/sh
# Telnet login wrapper — emits structured auth for collector JSONL parse.
# Full PTY transcript is collector-owned (pcap path); this only seeds credentials.

set -eu

JAIL="${AMBER_TELNET_JAIL:-/jail}"

printf 'AmberCell Telnet (lab)\r\n'
printf 'Login: '
IFS= read -r user || user=""
printf 'Password: '
IFS= read -r pass || pass=""

# KV line (legacy) + JSONL-friendly line for Stage-1 auth polish.
printf 'amber-auth: user=%s pass=%s\n' "$user" "$pass"
# shellcheck disable=SC2016
printf 'amber-auth-json: {"user":"%s","ok":true,"stage":"complete"}\n' "$user"

printf 'Welcome — disposable jail shell.\r\n'

if [ -d "$JAIL" ]; then
  cd "$JAIL" || cd /
else
  cd / || true
fi

export PS1='ambercell# '
export HOME="${JAIL}/home"
export PATH=/bin:/usr/bin

# Real interactive shell under containment.
exec /bin/sh -i
