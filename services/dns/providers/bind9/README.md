# AmberCell DNS hi-cell provider: bind9 (alternate)
#
# ISC BIND 9 (Alpine package) configured as an authoritative-only honeypot
# serving the same lure zones as the coredns default (`ambercell.lab`,
# `corp.example.net` with hr/finance/admin/support personas). Recursion
# disabled (`recursion no`, no forwarders) — never an open resolver (G13).
# CHAOS version.bind answers a stable `BIND 9.18.30` persona string.
#
# Select: AMBER_DNS_PROVIDER=bind9. Own image: AMBER_DNS_HI_IMAGE /
# AMBER_DNS_PROVIDER_CONTEXT (see docs/providers.md).
