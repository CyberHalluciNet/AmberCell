# Stage-6 — Samba sidecar profile (enforce on Linux hosts only).
#include <tunables/global>

profile ambercell-smb-hi flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>

  /usr/sbin/smbd ix,
  /shares/** rw,
  /var/log/samba/** rw,
  /var/lib/samba/** rw,
  /var/cache/samba/** rw,
  /run/amber/log/** w,
  /tmp/** rw,
  network,
  capability setuid,
  capability setgid,
  capability dac_override,
  capability net_bind_service,
}
