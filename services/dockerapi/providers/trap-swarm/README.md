# dockerapi provider `trap-swarm`

Docker Engine API trap with a fake **Swarm manager** surface (`/swarm`, `/nodes`, `/services`). Captures join/init/service-create intents. Never runs dockerd or a real swarm.

**Select:** `AMBER_DOCKERAPI_PROVIDER=trap-swarm`
