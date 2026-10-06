#!/bin/sh
set -eu

CONF_TEMPLATE="/etc/proftpd/proftpd.conf.template"
# Render under /tmp so the hi-cell can run with a read_only rootfs.
CONF="/tmp/proftpd.conf"
PASV_ADDR="${AMBER_FTP_PASV_ADDRESS:-}"

prod_mode=0
case ",${COMPOSE_PROFILES:-},${AMBER_PROFILE:-}," in
  *,production,*) prod_mode=1 ;;
esac

if [ -z "$PASV_ADDR" ]; then
  if [ "$prod_mode" -eq 1 ]; then
    echo "entrypoint: FATAL: AMBER_FTP_PASV_ADDRESS required in production (public IPv4)" >&2
    exit 1
  fi
  echo "entrypoint: AMBER_FTP_PASV_ADDRESS unset; using 127.0.0.1 (lab/CI only)" >&2
  PASV_ADDR="127.0.0.1"
fi
if [ "$PASV_ADDR" = "127.0.0.1" ] && [ "$prod_mode" -eq 1 ]; then
  echo "entrypoint: FATAL: AMBER_FTP_PASV_ADDRESS=127.0.0.1 invalid in production" >&2
  exit 1
fi

# Escape sed replacement metacharacters in the address
PASV_ESC=$(printf '%s' "$PASV_ADDR" | sed -e 's/[\\/&|]/\\&/g')
sed "s|@PASV_ADDRESS@|${PASV_ESC}|g" "$CONF_TEMPLATE" > "$CONF"

mkdir -p /tmp/proftpd
chmod 755 /tmp/proftpd

# Shared volume with collector may reset ownership; keep sticky upload dir.
mkdir -p /var/ftp/incoming
chmod 1733 /var/ftp/incoming || true

# -n: no daemonize (container PID 1 / docker stop)
exec /usr/sbin/proftpd -n -c "$CONF"
