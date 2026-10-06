# Stage-1 stub — minimal vsftpd-sidecar profile (enforce on Linux hosts only).
#include <tunables/global>

profile ambercell-ftp-hi flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/nameservice>

  /usr/sbin/vsftpd ix,
  /etc/vsftpd/** r,
  /etc/passwd r,
  /etc/group r,
  /var/ftp/** rw,
  /var/run/vsftpd/** rw,
  /tmp/** rw,
  network,
  capability net_bind_service,
  capability chown,
  capability setuid,
  capability setgid,
  capability sys_chroot,
  capability dac_override,
  capability fowner,
}
