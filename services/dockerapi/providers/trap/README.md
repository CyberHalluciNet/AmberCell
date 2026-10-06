# dockerapi provider `trap`

Sandboxed Docker Engine API mock for Wave D. Captures pull/run/mount/exec intents to the collector FIFO.

**Kill bars:** no host `docker.sock`, no `dockerd`, no privileged mode, no nested orchestration (G4/G8).
