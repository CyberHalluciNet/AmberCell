# AmberCell DNS hi-cell provider: unbound (alternate)
#
# NLnet Labs Unbound (Alpine package) in local-data honeypot mode: serves the
# same lure records as the coredns default, REFUSES everything else (`local-zone
# "." refuse`) — never an open resolver (G13). Stable persona identity/version
# strings for fingerprint consistency.
#
# Select: AMBER_DNS_PROVIDER=unbound. Own image: AMBER_DNS_HI_IMAGE /
# AMBER_DNS_PROVIDER_CONTEXT (see docs/providers.md).
