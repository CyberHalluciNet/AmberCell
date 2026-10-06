#!/bin/bash
set -euo pipefail

LOG_FIFO="${AMBER_SMB_LOG_FIFO:-/run/amber/log/smb.fifo}"
REALM="${AMBER_SMB_AD_REALM:-AMBERCELL.LAB}"
DOMAIN="${AMBER_SMB_AD_DOMAIN:-AMBERCELL}"
ADMINPASS="${AMBER_SMB_AD_ADMIN_PASS:-Welcome1!}"

mkdir -p "$(dirname "$LOG_FIFO")" /var/log/samba /var/lib/samba /shares/sysvol /shares/netlogon
if [ ! -p "$LOG_FIFO" ]; then
  rm -f "$LOG_FIFO"
  mkfifo "$LOG_FIFO"
  chmod 666 "$LOG_FIFO" 2>/dev/null || true
fi

if [ ! -f /var/lib/samba/private/sam.ldb ]; then
  rm -f /etc/samba/smb.conf
  samba-tool domain provision \
    --server-role=dc \
    --use-rfc2307 \
    --realm="$REALM" \
    --domain="$DOMAIN" \
    --adminpass="$ADMINPASS" \
    --dns-backend=SAMBA_INTERNAL \
    --option="interfaces=0.0.0.0" \
    --option="bind interfaces only=no" \
    2>&1 | tee -a "$LOG_FIFO" || {
      # Fallback: AD-lookalike file server if provision fails in constrained lab.
      cat >/etc/samba/smb.conf <<FALLBACK
[global]
   workgroup = ${DOMAIN}
   realm = ${REALM}
   server string = AmberCell AD Lure
   security = user
   domain logons = yes
   domain master = yes
   preferred master = yes
   log file = /var/log/samba/log.%m
   max log size = 50
   passdb backend = tdbsam

[netlogon]
   path = /shares/netlogon
   read only = no
   browsable = no

[sysvol]
   path = /shares/sysvol
   read only = no
FALLBACK
      (echo "$ADMINPASS"; echo "$ADMINPASS") | smbpasswd -a -s administrator 2>/dev/null || true
      echo "samba-ad: provision failed; running AD-lookalike file server" | tee -a "$LOG_FIFO"
      exec smbd -F -S 2>&1 | while IFS= read -r line; do
        printf '%s\n' "$line" >>"$LOG_FIFO" 2>/dev/null || true
        printf '%s\n' "$line"
      done
    }
fi

# Prefer samba (AD DC multi-service) when provisioned.
if command -v samba >/dev/null 2>&1 && [ -f /var/lib/samba/private/sam.ldb ]; then
  exec samba -i -M single 2>&1 | while IFS= read -r line; do
    printf '%s\n' "$line" >>"$LOG_FIFO" 2>/dev/null || true
    printf '%s\n' "$line"
  done
fi

exec smbd -F -S 2>&1 | while IFS= read -r line; do
  printf '%s\n' "$line" >>"$LOG_FIFO" 2>/dev/null || true
  printf '%s\n' "$line"
done
