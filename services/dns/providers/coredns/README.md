# AmberCell DNS hi-cell provider: coredns (default)
#
# Ships the official pinned CoreDNS binary configured as an authoritative-only
# honeypot: lure zones `ambercell.lab` (mail/vpn/dev/staging/git/jenkins/backup
# A records + TXT lure) and `corp.example.net` (hr/finance/admin/support
# personas matching the SMTP/POP3 lure mailboxes). Everything else REFUSED —
# no recursion (G13). CHAOS version.bind answers a stable
# `ambercell-dns-1.0` persona string.
#
# Select: AMBER_DNS_PROVIDER=coredns (default). Own image:
# AMBER_DNS_HI_IMAGE / AMBER_DNS_PROVIDER_CONTEXT (see docs/providers.md).
