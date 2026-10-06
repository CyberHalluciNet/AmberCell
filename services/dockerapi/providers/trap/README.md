# dockerapi provider `trap` (default)

Sandboxed Docker Engine API mock for Wave D. Captures pull/run/mount/exec intents to the collector FIFO.

**Select:** `AMBER_DOCKERAPI_PROVIDER=trap`  
**Profile:** `AMBER_DOCKERAPI_TRAP_PROFILE=default` (shared helper under `services/dockerapi/trap_helper/`)

**Kill bars:** no host `docker.sock`, no `dockerd`, no privileged mode, no nested orchestration (G4/G8).

## Alternates

| Provider | Focus |
| --- | --- |
| `trap-v1.41` | Older Engine / API 1.41 banner |
| `trap-swarm` | Fake Swarm manager (`/swarm`, `/services`, `/nodes`) |
