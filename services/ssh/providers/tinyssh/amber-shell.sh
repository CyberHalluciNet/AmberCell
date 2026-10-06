#!/bin/sh
# Interactive SSH wrapper — structured lines for ssh-collector FIFO parse.
set -eu

LOG_FIFO="${AMBER_SSH_LOG_FIFO:-/run/amber/log/ssh.fifo}"
UPLOAD="${AMBER_SSH_UPLOAD_DIR:-/mnt/uploads}"

log_json() {
  # shellcheck disable=SC2059
  printf '%s\n' "$1" >>"$LOG_FIFO" 2>/dev/null || true
}

user="${USER:-unknown}"
log_json "amber-ssh-json:{\"event\":\"session_open\",\"user\":\"${user}\",\"ok\":true}"

export PS1='ambercell$ '
export HOME="${HOME:-/home/${user}}"
export PATH=/bin:/usr/bin:/sbin:/usr/sbin

cd "$HOME" 2>/dev/null || cd / || true
printf 'AmberCell SSH lab shell (disposable).\n'
printf 'Uploads land in %s (SFTP/scp).\n' "$UPLOAD"

# Real interactive shell; collector owns encrypted channel + FIFO auth lines.
exec /bin/sh -i
