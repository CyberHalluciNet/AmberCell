# Stage-5 — openssh sidecar profile (enforce on Linux hosts only).
#include <tunables/global>

profile ambercell-ssh-hi flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>
  #include <abstractions/nameservice>

  /usr/sbin/sshd ix,
  /usr/local/bin/amber-shell.sh ix,
  /bin/sh ix,
  /usr/bin/script ix,
  /run/sshd/** rw,
  /run/amber/log/** w,
  /mnt/uploads/** rw,
  /home/** rw,
  /tmp/** rw,
  /dev/pts/** rw,
  /dev/ptmx rw,
  network,
  capability net_bind_service,
  capability setuid,
  capability setgid,
  capability sys_chroot,
  capability chown,
  capability dac_override,
}
