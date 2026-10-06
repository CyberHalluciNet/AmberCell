# kubelet provider `trap` (default)

Standalone fake kubelet HTTP API for Wave D. Captures pod/exec/attach probes. **Never** a real cluster.

**Select:** `AMBER_KUBELET_PROVIDER=trap`  
**Shared helper:** `services/kubelet/trap_helper/trap_server.py`

## Alternates

| Provider | Focus |
| --- | --- |
| `trap-unauth` | Open unauthenticated surface (`/metrics`, `/runningpods`) |
| `trap-exec` | Exec/attach-focused capture |
