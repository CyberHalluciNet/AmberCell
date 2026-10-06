# SSH provider: openssh (default)

**Protocol cell:** `ssh`  
**Provider id:** `openssh`  
**Select:** `AMBER_SSH_PROVIDER=openssh`

## Contract

- Real OpenSSH `sshd`; PTY via `amber-shell.sh` + collector FIFO; SFTP/scp uploads on shared `/mnt/uploads`.
- Honeypot owns public `tcp/22` via nft DNAT — **G9:** admin SSH must use another port/path.
- Alternate: [`../dropbear/`](../dropbear/) (stub slot).

## Lure accounts (lab)

| User | Password |
| --- | --- |
| admin | admin123 |
| support | support |
| lure | lure |

## Implementation

Stage-5 Wave A — see `compose.yaml` profile `wave-a`, collector `collectors/ssh/`.
