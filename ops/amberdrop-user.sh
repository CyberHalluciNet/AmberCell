#!/usr/bin/env bash
# Create read-only dead-drop consumer (G11). Run on Linux production host only.
set -euo pipefail
if ! id amberdrop &>/dev/null; then
  useradd -r -s /usr/sbin/nologin -d /nonexistent -M amberdrop
fi
install -d -o root -g amber-drop -m 0750 /var/ambercell/deaddrop
echo "amberdrop user ready; grant read via group amber-drop on /var/ambercell/deaddrop only"
