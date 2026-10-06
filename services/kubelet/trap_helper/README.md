# kubelet trap_helper

Canonical profile-aware fake kubelet (`trap_server.py`).

Sync into provider contexts after edits:

```bash
for d in trap trap-unauth trap-exec; do
  cp services/kubelet/trap_helper/trap_server.py "services/kubelet/providers/$d/trap_server.py"
done
```

Profiles: `default` | `unauth` | `exec` via `AMBER_KUBELET_TRAP_PROFILE`.
