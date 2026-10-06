# Shared trap helper (dockerapi / kubelet)

Canonical profile-aware trap servers live next to each cell:

- `services/dockerapi/trap_helper/trap_server.py`
- `services/kubelet/trap_helper/trap_server.py`

Each provider directory embeds a copy of the helper (Compose build context is per-provider). Edit the cell `trap_helper/` copy, then re-sync into `providers/*/trap_server.py`. Never embed a real dockerd or Kubernetes control plane.

| Cell | Provider ids | Profile env |
| --- | --- | --- |
| dockerapi | `trap`, `trap-v1.41`, `trap-swarm` | `AMBER_DOCKERAPI_TRAP_PROFILE` |
| kubelet | `trap`, `trap-unauth`, `trap-exec` | `AMBER_KUBELET_TRAP_PROFILE` |

**Kill bars:** never mount `docker.sock`, never run `dockerd`, never join a real cluster.
