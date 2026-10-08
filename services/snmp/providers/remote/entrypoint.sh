#!/bin/sh
# Remote tunnel provider: relay cell traffic to the operator's own snmp server
# (AMBER_SNMP_REMOTE_ADDR=host:port). The backend must be reachable from the cell
# (see nftables egress remote-backend allowlist, G14). TFTP caveat: only the
# udp/69 control channel is relayed; TFTP data channels negotiate new ports.
set -eu

: "${AMBER_SNMP_REMOTE_ADDR:?remote provider requires AMBER_SNMP_REMOTE_ADDR=host:port}"
AMBER_SNMP_REMOTE_TRANSPORT="${AMBER_SNMP_REMOTE_TRANSPORT:-both}"

if [ "$AMBER_SNMP_REMOTE_TRANSPORT" = "udp" ] || [ "$AMBER_SNMP_REMOTE_TRANSPORT" = "both" ]; then
  if [ "udp" = tcp ]; then
    socat TCP-LISTEN:161,fork,reuseaddr,bind=0.0.0.0 TCP:"$AMBER_SNMP_REMOTE_ADDR" &
  else
    socat -T5 UDP4-RECVFROM:161,fork UDP4-SENDTO:"$AMBER_SNMP_REMOTE_ADDR" &
  fi
fi
if [ "$AMBER_SNMP_REMOTE_TRANSPORT" = "tcp" ] || [ "$AMBER_SNMP_REMOTE_TRANSPORT" = "both" ]; then
  if [ "tcp" = tcp ]; then
    socat TCP-LISTEN:161,fork,reuseaddr,bind=0.0.0.0 TCP:"$AMBER_SNMP_REMOTE_ADDR" &
  else
    socat -T5 UDP4-RECVFROM:161,fork UDP4-SENDTO:"$AMBER_SNMP_REMOTE_ADDR" &
  fi
fi

wait
