// SPDX-License-Identifier: LicenseRef-AmberCell-PSL-1.0

package cli

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/CyberHalluciNet/AmberCell/amberctl/internal/compose"
	"github.com/CyberHalluciNet/AmberCell/amberctl/internal/paths"
)

type probeTarget struct {
	Svc    string
	Host   string
	Port   int
	Banner string // empty = any non-empty read OK
}

// runLiveness probes TCP+banner every 30s; 3 fails → snapshot_then_rebuild path.
func runLiveness(args []string) error {
	fsInterval := 30 * time.Second
	once := false
	svcs := []string{"ftp", "telnet", "smtp", "pop3"}
	for _, a := range args {
		switch a {
		case "--once":
			once = true
		case "ftp", "telnet", "smtp", "pop3", "ssh", "redis", "mqtt", "http", "mysql", "postgres", "smb", "mongo", "elastic", "dockerapi", "kubelet", "ollama", "dns", "tftp", "snmp", "ntp", "syslog", "sip", "ldap", "imap", "memcached", "rdp", "vnc", "netbios":
			svcs = []string{a}
		case "-h", "--help":
			fmt.Fprintln(os.Stderr, "usage: amberctl liveness [--once] [svc]")
			return nil
		}
	}

	fails := map[string]int{}
	for {
		for _, svc := range svcs {
			t, err := probeFor(svc)
			if err != nil {
				fmt.Fprintf(os.Stderr, "amberctl: liveness %s: config: %v\n", svc, err)
				continue
			}
			ok, detail := probeOnce(t)
			statePath := filepath.Join(paths.EvidenceRoot(), "state", svc+".liveness.json")
			rec := map[string]any{
				"svc":        svc,
				"ts":         time.Now().UTC().Format(time.RFC3339Nano),
				"ok":         ok,
				"detail":     detail,
				"addr":       net.JoinHostPort(t.Host, strconv.Itoa(t.Port)),
				"fail_count": fails[svc],
			}
			if ok {
				fails[svc] = 0
				rec["fail_count"] = 0
				fmt.Fprintf(os.Stderr, "amberctl: liveness %s OK %s\n", svc, detail)
			} else {
				fails[svc]++
				rec["fail_count"] = fails[svc]
				fmt.Fprintf(os.Stderr, "amberctl: liveness %s FAIL (%d/3) %s\n", svc, fails[svc], detail)
				if fails[svc] >= 3 {
					rec["action"] = "snapshot_then_rebuild"
					_ = writeJSON(statePath, rec)
					fmt.Fprintf(os.Stderr, "amberctl: liveness %s → snapshot_then_rebuild (independent of AI)\n", svc)
					if err := triggerLivenessRebuild(svc); err != nil {
						fmt.Fprintf(os.Stderr, "amberctl: liveness rebuild %s: %v\n", svc, err)
					}
					fails[svc] = 0
				}
			}
			_ = writeJSON(statePath, rec)
		}
		if once {
			return nil
		}
		time.Sleep(fsInterval)
	}
}

func probeFor(svc string) (probeTarget, error) {
	host, port, err := resolveProbeAddr(svc)
	if err != nil {
		return probeTarget{}, err
	}
	t := probeTarget{Svc: svc, Host: host, Port: port}
	switch svc {
	case "ftp", "smtp":
		t.Banner = "220"
	case "pop3":
		t.Banner = "+OK"
	case "ssh":
		t.Banner = "SSH-"
	case "http", "elastic", "dockerapi", "kubelet", "ollama":
		t.Banner = "HTTP/"
	}
	return t, nil
}

func probeOnce(t probeTarget) (bool, string) {
	// DNS is UDP: send a lure-zone A query and expect a NOERROR response.
	if t.Svc == "dns" {
		detail, err := dnsUDPProbe(t.Host, t.Port)
		if err != nil {
			return false, err.Error()
		}
		return true, detail
	}
	// Wave G request-response probes (UDP/TCP per protocol).
	switch t.Svc {
	case "tftp", "snmp", "ntp", "sip", "ldap", "syslog", "imap", "memcached", "rdp", "vnc", "netbios":
		var detail string
		var err error
		switch t.Svc {
		case "tftp":
			detail, err = probeTFTP(t.Host, t.Port)
		case "snmp":
			detail, err = probeSNMP(t.Host, t.Port)
		case "ntp":
			detail, err = probeNTP(t.Host, t.Port)
		case "sip":
			detail, err = probeSIP(t.Host, t.Port)
		case "ldap":
			detail, err = probeLDAP(t.Host, t.Port)
		case "syslog":
			detail, err = probeSyslog(t.Host, t.Port)
		case "imap":
			detail, err = probeIMAP(t.Host, t.Port)
		case "memcached":
			detail, err = probeMemcached(t.Host, t.Port)
		case "rdp":
			detail, err = probeRDP(t.Host, t.Port)
		case "vnc":
			detail, err = probeVNC(t.Host, t.Port)
		case "netbios":
			detail, err = probeNetbios(t.Host, t.Port)
		}
		if err != nil {
			return false, err.Error()
		}
		return true, detail
	}
	addr := net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return false, err.Error()
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if t.Svc == "redis" {
		_, _ = conn.Write([]byte("*1\r\n$4\r\nPING\r\n"))
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, err = conn.Read(buf)
	}
	if t.Svc == "http" || t.Svc == "elastic" {
		_, _ = conn.Write([]byte("GET / HTTP/1.0\r\nHost: localhost\r\n\r\n"))
		_ = conn.SetReadDeadline(time.Now().Add(8 * time.Second))
		n, err = conn.Read(buf)
	}
	if t.Svc == "dockerapi" {
		_, _ = conn.Write([]byte("GET /version HTTP/1.0\r\nHost: localhost\r\n\r\n"))
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, err = conn.Read(buf)
	}
	if t.Svc == "kubelet" {
		_, _ = conn.Write([]byte("GET /healthz HTTP/1.0\r\nHost: localhost\r\n\r\n"))
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, err = conn.Read(buf)
	}
	if t.Svc == "ollama" {
		_, _ = conn.Write([]byte("GET /api/tags HTTP/1.0\r\nHost: localhost\r\n\r\n"))
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, err = conn.Read(buf)
	}
	if n == 0 && err != nil {
		if t.Svc == "mqtt" || t.Svc == "mysql" || t.Svc == "postgres" || t.Svc == "smb" || t.Svc == "mongo" {
			return true, "tcp_ok"
		}
		return false, err.Error()
	}
	snippet := strings.TrimSpace(string(buf[:n]))
	if t.Svc == "mqtt" && snippet == "" {
		return true, "tcp_ok"
	}
	if t.Banner != "" && !strings.HasPrefix(snippet, t.Banner) {
		return false, fmt.Sprintf("banner mismatch: %q", truncate(snippet, 60))
	}
	return true, truncate(snippet, 60)
}

func triggerLivenessRebuild(svc string) error {
	if !supportedCell(svc) {
		return fmt.Errorf("unknown svc")
	}
	// Write decision-shaped audit record, then rebuild (cooldown still applies).
	decDir := filepath.Join(paths.EvidenceRoot(), "decisions", svc)
	_ = os.MkdirAll(decDir, 0o750)
	dec := map[string]any{
		"schema_version":     "decision.v1",
		"decision_id":        fmt.Sprintf("dec_live_%d", time.Now().Unix()),
		"ts":                 time.Now().UTC().Format(time.RFC3339Nano),
		"scope":              "cell",
		"target_id":          svc,
		"cell_id":            svc + "-cell-01",
		"decision_type":      "snapshot_then_rebuild",
		"confidence":         "high",
		"severity":           "high",
		"reason_summary":     "liveness probe failed 3 consecutive times",
		"evidence_refs":      []string{},
		"policy_refs":        []string{"liveness.v1"},
		"recommended_action": "snapshot_then_rebuild",
		"executor_status":    "pending",
		"decision_version":   "2026-10-06.1",
		"source":             "liveness_probe",
	}
	_ = writeJSON(filepath.Join(decDir, dec["decision_id"].(string)+".json"), dec)
	return withLifecycleLock(svc, "liveness-rebuild", func() error {
		if err := compose.StopHI(svc); err != nil {
			return err
		}
		time.Sleep(2 * time.Second)
		_ = compose.StopCollector(svc)
		return compose.UpCell(svc)
	})
}

func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o640)
}
