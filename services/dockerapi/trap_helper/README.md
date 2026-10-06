# dockerapi trap_helper

Canonical profile-aware Docker Engine API trap (`trap_server.py`).

Sync into provider contexts after edits:

```bash
for d in trap trap-v1.41 trap-swarm; do
  cp services/dockerapi/trap_helper/trap_server.py "services/dockerapi/providers/$d/trap_server.py"
done
```

Profiles: `default` | `v1.41` | `swarm` via `AMBER_DOCKERAPI_TRAP_PROFILE`.
