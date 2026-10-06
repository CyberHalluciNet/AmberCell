# Stage-5 — redis-server sidecar profile (enforce on Linux hosts only).
#include <tunables/global>

profile ambercell-redis-hi flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>

  /usr/local/bin/redis-server ix,
  /data/** rw,
  /run/amber/log/** w,
  /tmp/** rw,
  network,
  capability setuid,
  capability setgid,
  capability dac_override,
}
