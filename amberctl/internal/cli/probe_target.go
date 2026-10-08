// SPDX-License-Identifier: LicenseRef-AmberCell-PSL-1.0

package cli

import (
	"fmt"
	"os"
	"strconv"

	"github.com/CyberHalluciNet/AmberCell/amberctl/internal/compose"
)

// nativePort is the in-cell listen port for each protocol.
var nativePort = map[string]int{
	"ftp":       21,
	"telnet":    23,
	"smtp":      25,
	"pop3":      110,
	"ssh":       22,
	"redis":     6379,
	"mqtt":      1883,
	"http":      80,
	"mysql":     3306,
	"postgres":  5432,
	"smb":       445,
	"mongo":     27017,
	"elastic":   9200,
	"dockerapi": 2375,
	"kubelet":   10250,
	"ollama":    11434,
	"dns":       53,
	"tftp":      69,
	"snmp":      161,
	"ntp":       123,
	"syslog":    514,
	"sip":       5060,
	"ldap":      389,
	"imap":      143,
	"memcached": 11211,
	"rdp":       3389,
	"vnc":       5900,
	"netbios":   137,
}

// labHostPortEnv maps svc → env var for lab published host port.
var labHostPortEnv = map[string]string{
	"ftp":       "AMBER_FTP_HOST_PORT",
	"telnet":    "AMBER_TELNET_HOST_PORT",
	"smtp":      "AMBER_SMTP_HOST_PORT",
	"pop3":      "AMBER_POP3_HOST_PORT",
	"ssh":       "AMBER_SSH_HOST_PORT",
	"redis":     "AMBER_REDIS_HOST_PORT",
	"mqtt":      "AMBER_MQTT_HOST_PORT",
	"http":      "AMBER_HTTP_HOST_PORT",
	"mysql":     "AMBER_MYSQL_HOST_PORT",
	"postgres":  "AMBER_POSTGRES_HOST_PORT",
	"smb":       "AMBER_SMB_HOST_PORT",
	"mongo":     "AMBER_MONGO_HOST_PORT",
	"elastic":   "AMBER_ELASTIC_HOST_PORT",
	"dockerapi": "AMBER_DOCKERAPI_HOST_PORT",
	"kubelet":   "AMBER_KUBELET_HOST_PORT",
	"ollama":    "AMBER_OLLAMA_HOST_PORT",
	"dns":       "AMBER_DNS_HOST_PORT",
	"tftp":      "AMBER_TFTP_HOST_PORT",
	"snmp":      "AMBER_SNMP_HOST_PORT",
	"ntp":       "AMBER_NTP_HOST_PORT",
	"syslog":    "AMBER_SYSLOG_HOST_PORT",
	"sip":       "AMBER_SIP_HOST_PORT",
	"ldap":      "AMBER_LDAP_HOST_PORT",
	"imap":      "AMBER_IMAP_HOST_PORT",
	"memcached": "AMBER_MEMCACHED_HOST_PORT",
	"rdp":       "AMBER_RDP_HOST_PORT",
	"vnc":       "AMBER_VNC_HOST_PORT",
	"netbios":   "AMBER_NETBIOS_HOST_PORT",
}

var labHostPortDefault = map[string]string{
	"ftp":       "21",
	"telnet":    "2323",
	"smtp":      "2525",
	"pop3":      "1110",
	"ssh":       "2222",
	"redis":     "6379",
	"mqtt":      "1883",
	"http":      "8080",
	"mysql":     "3306",
	"postgres":  "5432",
	"smb":       "445",
	"mongo":     "27017",
	"elastic":   "9200",
	"dockerapi": "2375",
	"kubelet":   "10250",
	"ollama":    "11434",
	"dns":       "1053",
	"tftp":      "1069",
	"snmp":      "1161",
	"ntp":       "1123",
	"syslog":    "1514",
	"sip":       "15060",
	"ldap":      "1389",
	"imap":      "1143",
	"memcached": "11211",
	"rdp":       "13389",
	"vnc":       "15900",
	"netbios":   "1137",
}

var drillHostEnv = map[string]string{
	"ftp":       "AMBER_FTP_DRILL_HOST",
	"telnet":    "AMBER_TELNET_DRILL_HOST",
	"smtp":      "AMBER_SMTP_DRILL_HOST",
	"pop3":      "AMBER_POP3_DRILL_HOST",
	"ssh":       "AMBER_SSH_DRILL_HOST",
	"redis":     "AMBER_REDIS_DRILL_HOST",
	"mqtt":      "AMBER_MQTT_DRILL_HOST",
	"http":      "AMBER_HTTP_DRILL_HOST",
	"mysql":     "AMBER_MYSQL_DRILL_HOST",
	"postgres":  "AMBER_POSTGRES_DRILL_HOST",
	"smb":       "AMBER_SMB_DRILL_HOST",
	"mongo":     "AMBER_MONGO_DRILL_HOST",
	"elastic":   "AMBER_ELASTIC_DRILL_HOST",
	"dockerapi": "AMBER_DOCKERAPI_DRILL_HOST",
	"kubelet":   "AMBER_KUBELET_DRILL_HOST",
	"ollama":    "AMBER_OLLAMA_DRILL_HOST",
	"dns":       "AMBER_DNS_DRILL_HOST",
	"tftp":      "AMBER_TFTP_DRILL_HOST",
	"snmp":      "AMBER_SNMP_DRILL_HOST",
	"ntp":       "AMBER_NTP_DRILL_HOST",
	"syslog":    "AMBER_SYSLOG_DRILL_HOST",
	"sip":       "AMBER_SIP_DRILL_HOST",
	"ldap":      "AMBER_LDAP_DRILL_HOST",
	"imap":      "AMBER_IMAP_DRILL_HOST",
	"memcached": "AMBER_MEMCACHED_DRILL_HOST",
	"rdp":       "AMBER_RDP_DRILL_HOST",
	"vnc":       "AMBER_VNC_DRILL_HOST",
	"netbios":   "AMBER_NETBIOS_DRILL_HOST",
}

// resolveProbeAddr picks production cell IP+native port when production profile
// is active (no Compose published ports). Lab keeps localhost + remapped ports.
func resolveProbeAddr(svc string) (host string, port int, err error) {
	if _, ok := compose.Cells[svc]; !ok {
		return "", 0, fmt.Errorf("unsupported %q", svc)
	}
	// Explicit drill host always wins.
	if h := os.Getenv(drillHostEnv[svc]); h != "" {
		host = h
	} else if productionProfilesActive() && !labProfilesActive() {
		host = compose.CellIP(svc)
	} else {
		host = "127.0.0.1"
	}

	if productionProfilesActive() && !labProfilesActive() {
		port = nativePort[svc]
		// Allow override via AMBER_*_HOST_PORT even in production (rare).
		if env := labHostPortEnv[svc]; env != "" {
			if v := os.Getenv(env); v != "" {
				port, err = strconv.Atoi(v)
				if err != nil {
					return "", 0, err
				}
			}
		}
		return host, port, nil
	}

	def := labHostPortDefault[svc]
	port, err = strconv.Atoi(envOr(labHostPortEnv[svc], def))
	if err != nil {
		return "", 0, err
	}
	return host, port, nil
}
