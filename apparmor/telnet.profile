# Stage-1 — busybox-telnetd sidecar profile (enforce on Linux hosts only).
#include <tunables/global>

profile ambercell-telnet-hi flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>
  #include <abstractions/nameservice>

  /usr/sbin/telnetd ix,
  /usr/sbin/amber-login ix,
  /bin/busybox ix,
  /bin/sh ix,
  /jail/** rw,
  /jail/bin/** ix,
  /var/run/telnetd/** rw,
  /tmp/** rw,
  /proc/*/fd/ r,
  /dev/pts/** rw,
  /dev/ptmx rw,
  network,
  capability net_bind_service,
  capability setuid,
  capability setgid,
  capability sys_chroot,
}
