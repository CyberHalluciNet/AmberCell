// SPDX-License-Identifier: LicenseRef-AmberCell-PSL-1.0

package wizard

import (
	"os"
	"path/filepath"
	"sort"

	"github.com/CyberHalluciNet/AmberCell/amberctl/internal/compose"
)

// ProviderOption is a premade provider id with a one-line description.
type ProviderOption struct {
	ID   string
	Desc string
}

// CellOption describes a protocol cell for the init wizard.
type CellOption struct {
	Svc         string
	CoreDefault bool // offered in the "core four" default selection
	Providers   []ProviderOption
	ExtraHint   string // e.g. PASV for FTP
}

// Catalog is the planned premade matrix (wizard lists only those with a Dockerfile).
var Catalog = []CellOption{
	{Svc: "ftp", CoreDefault: true, ExtraHint: "AMBER_FTP_PASV_ADDRESS", Providers: []ProviderOption{
		{ID: "vsftpd", Desc: "vsftpd (default FTP)"},
		{ID: "proftpd", Desc: "ProFTPD"},
		{ID: "pure-ftpd", Desc: "Pure-FTPd"},
	}},
	{Svc: "smtp", CoreDefault: true, Providers: []ProviderOption{
		{ID: "postfix", Desc: "Postfix (default SMTP)"},
		{ID: "exim", Desc: "Exim"},
		{ID: "opensmtpd", Desc: "OpenSMTPD"},
	}},
	{Svc: "pop3", CoreDefault: true, Providers: []ProviderOption{
		{ID: "dovecot", Desc: "Dovecot (default POP3)"},
		{ID: "cyrus", Desc: "Cyrus IMAP/POP3"},
		{ID: "courier", Desc: "Courier"},
	}},
	{Svc: "telnet", CoreDefault: true, Providers: []ProviderOption{
		{ID: "busybox-telnetd", Desc: "BusyBox telnetd (default)"},
		{ID: "inetutils-telnetd", Desc: "GNU inetutils telnetd"},
		{ID: "netkit-telnetd", Desc: "NetKit telnetd"},
	}},
	{Svc: "ssh", Providers: []ProviderOption{
		{ID: "openssh", Desc: "OpenSSH"},
		{ID: "dropbear", Desc: "Dropbear"},
		{ID: "tinyssh", Desc: "TinySSH"},
	}},
	{Svc: "redis", Providers: []ProviderOption{
		{ID: "redis-server", Desc: "Redis"},
		{ID: "valkey", Desc: "Valkey"},
		{ID: "keydb", Desc: "KeyDB"},
	}},
	{Svc: "mqtt", Providers: []ProviderOption{
		{ID: "mosquitto", Desc: "Eclipse Mosquitto"},
		{ID: "nanomq", Desc: "NanoMQ"},
		{ID: "emqx", Desc: "EMQX"},
	}},
	{Svc: "http", Providers: []ProviderOption{
		{ID: "nginx", Desc: "nginx"},
		{ID: "httpd", Desc: "Apache httpd"},
		{ID: "caddy", Desc: "Caddy"},
	}},
	{Svc: "mysql", Providers: []ProviderOption{
		{ID: "mariadb", Desc: "MariaDB"},
		{ID: "percona", Desc: "Percona Server"},
		{ID: "mysql", Desc: "MySQL"},
	}},
	{Svc: "postgres", Providers: []ProviderOption{
		{ID: "postgresql", Desc: "PostgreSQL"},
		{ID: "pgvector", Desc: "pgvector"},
		{ID: "timescaledb", Desc: "TimescaleDB"},
	}},
	{Svc: "smb", Providers: []ProviderOption{
		{ID: "samba", Desc: "Samba"},
		{ID: "samba-ad", Desc: "Samba AD DC bait"},
		{ID: "samba-shares", Desc: "Samba multi-share"},
	}},
	{Svc: "mongo", Providers: []ProviderOption{
		{ID: "ferretdb", Desc: "FerretDB"},
		{ID: "mock", Desc: "Mock document trap"},
		{ID: "mongodb", Desc: "MongoDB"},
	}},
	{Svc: "elastic", Providers: []ProviderOption{
		{ID: "opensearch", Desc: "OpenSearch"},
		{ID: "zincsearch", Desc: "ZincSearch"},
		{ID: "elasticsearch", Desc: "Elasticsearch"},
	}},
	{Svc: "dockerapi", Providers: []ProviderOption{
		{ID: "trap", Desc: "Docker API trap"},
		{ID: "trap-v1.41", Desc: "API v1.41 trap"},
		{ID: "trap-swarm", Desc: "Swarm-flavored trap"},
	}},
	{Svc: "kubelet", Providers: []ProviderOption{
		{ID: "trap", Desc: "Kubelet trap"},
		{ID: "trap-unauth", Desc: "Unauth kubelet trap"},
		{ID: "trap-exec", Desc: "Exec-path trap"},
	}},
	{Svc: "ollama", Providers: []ProviderOption{
		{ID: "mock", Desc: "Ollama mock"},
		{ID: "ollama", Desc: "Ollama"},
		{ID: "localai", Desc: "LocalAI"},
	}},
	{Svc: "dns", ExtraHint: "AMBER_DNS_HOST_PORT", Providers: []ProviderOption{
		{ID: "coredns", Desc: "CoreDNS (default DNS)"},
		{ID: "bind9", Desc: "ISC BIND9"},
		{ID: "unbound", Desc: "Unbound"},
	}},
	{Svc: "imap", Providers: []ProviderOption{
		{ID: "dovecot", Desc: "Dovecot IMAP (default)"},
		{ID: "remote", Desc: "Relay to own server (AMBER_IMAP_REMOTE_ADDR)"},
	}},
	{Svc: "memcached", Providers: []ProviderOption{
		{ID: "memcached", Desc: "memcached (default; empty NOT_FOUND answers)"},
		{ID: "remote", Desc: "Relay to own server (AMBER_MEMCACHED_REMOTE_ADDR)"},
	}},
	{Svc: "rdp", Providers: []ProviderOption{
		{ID: "xrdp", Desc: "xrdp (default; negotiation/TLS surface)"},
		{ID: "remote", Desc: "Relay to own server (AMBER_RDP_REMOTE_ADDR)"},
	}},
	{Svc: "vnc", Providers: []ProviderOption{
		{ID: "tigervnc", Desc: "TigerVNC Xvnc (default)"},
		{ID: "remote", Desc: "Relay to own server (AMBER_VNC_REMOTE_ADDR)"},
	}},
	{Svc: "netbios", Providers: []ProviderOption{
		{ID: "nmbd", Desc: "samba nmbd (default)"},
		{ID: "remote", Desc: "Relay to own server (AMBER_NETBIOS_REMOTE_ADDR)"},
	}},
	{Svc: "tftp", Providers: []ProviderOption{
		{ID: "dnsmasq", Desc: "dnsmasq TFTP (default; fixed transfer range)"},
		{ID: "tftpd-hpa", Desc: "tftpd-hpa"},
		{ID: "atftpd", Desc: "atftpd"},
		{ID: "remote", Desc: "Relay to own server (AMBER_TFTP_REMOTE_ADDR)"},
	}},
	{Svc: "snmp", Providers: []ProviderOption{
		{ID: "snmpd", Desc: "net-snmp snmpd (default, alpine)"},
		{ID: "snmpd-debian", Desc: "net-snmp snmpd (debian)"},
		{ID: "remote", Desc: "Relay to own agent (AMBER_SNMP_REMOTE_ADDR)"},
	}},
	{Svc: "ntp", Providers: []ProviderOption{
		{ID: "chrony", Desc: "chrony (default NTP)"},
		{ID: "openntpd", Desc: "OpenNTPD"},
		{ID: "ntp-classic", Desc: "ntp.org classic"},
		{ID: "remote", Desc: "Relay to own server (AMBER_NTP_REMOTE_ADDR)"},
	}},
	{Svc: "syslog", Providers: []ProviderOption{
		{ID: "rsyslog", Desc: "rsyslog (default)"},
		{ID: "syslog-ng", Desc: "syslog-ng"},
		{ID: "remote", Desc: "Relay to own server (AMBER_SYSLOG_REMOTE_ADDR)"},
	}},
	{Svc: "sip", Providers: []ProviderOption{
		{ID: "kamailio", Desc: "Kamailio (default SIP)"},
		{ID: "opensips", Desc: "OpenSIPS"},
		{ID: "remote", Desc: "Relay to own server (AMBER_SIP_REMOTE_ADDR)"},
	}},
	{Svc: "ldap", Providers: []ProviderOption{
		{ID: "openldap", Desc: "OpenLDAP slapd (default)"},
		{ID: "glauth", Desc: "GLAuth"},
		{ID: "remote", Desc: "Relay to own server (AMBER_LDAP_REMOTE_ADDR)"},
	}},
}

// AvailableProviders returns premade providers that have a Dockerfile under root.
func AvailableProviders(root string, cell CellOption) []ProviderOption {
	var out []ProviderOption
	for _, p := range cell.Providers {
		df := filepath.Join(root, "services", cell.Svc, "providers", p.ID, "Dockerfile")
		if fileExists(df) {
			out = append(out, p)
		}
	}
	return out
}

// CoreDefaultSvcs returns svc names marked CoreDefault, in catalog order.
func CoreDefaultSvcs() []string {
	var out []string
	for _, c := range Catalog {
		if c.CoreDefault {
			out = append(out, c.Svc)
		}
	}
	return out
}

// AllSvcNames returns all catalog svc names.
func AllSvcNames() []string {
	out := make([]string, 0, len(Catalog))
	for _, c := range Catalog {
		out = append(out, c.Svc)
	}
	return out
}

// CellBySvc looks up a catalog entry.
func CellBySvc(svc string) (CellOption, bool) {
	for _, c := range Catalog {
		if c.Svc == svc {
			return c, true
		}
	}
	// Fall back to compose.Cells for unknown-but-valid cells.
	if spec, ok := compose.Cells[svc]; ok {
		return CellOption{
			Svc: svc,
			Providers: []ProviderOption{{
				ID:   spec.DefaultProv,
				Desc: spec.DefaultProv + " (default)",
			}},
		}, true
	}
	return CellOption{}, false
}

// KnownSvcsSorted returns compose cell names sorted.
func KnownSvcsSorted() []string {
	out := make([]string, 0, len(compose.Cells))
	for k := range compose.Cells {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func fileExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
}
