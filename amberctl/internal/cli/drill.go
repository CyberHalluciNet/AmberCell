// SPDX-License-Identifier: LicenseRef-AmberCell-PSL-1.0

package cli

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

func runDrill(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: amberctl drill ftp|telnet|smtp|pop3|ssh|redis|mqtt|http|mysql|postgres|smb|mongo|elastic|dockerapi|kubelet|ollama|dns|tftp|snmp|ntp|syslog|sip|ldap|imap|memcached|rdp|vnc|netbios")
	}
	switch args[0] {
	case "ftp":
		return drillFTP()
	case "telnet":
		return drillTelnet()
	case "smtp":
		return drillSMTP()
	case "pop3":
		return drillPOP3()
	case "ssh":
		return drillSSH()
	case "redis":
		return drillRedis()
	case "mqtt":
		return drillMQTT()
	case "http":
		return drillHTTP()
	case "mysql":
		return drillMySQL()
	case "postgres":
		return drillPostgres()
	case "smb":
		return drillSMB()
	case "mongo":
		return drillMongo()
	case "elastic":
		return drillElastic()
	case "dockerapi":
		return drillDockerapi()
	case "kubelet":
		return drillKubelet()
	case "ollama":
		return drillOllama()
	case "dns":
		return drillDNS()
	case "tftp":
		return drillTFTP()
	case "snmp":
		return drillSNMP()
	case "ntp":
		return drillNTP()
	case "syslog":
		return drillSyslog()
	case "sip":
		return drillSIP()
	case "ldap":
		return drillLDAP()
	case "imap":
		return drillIMAP()
	case "memcached":
		return drillMemcached()
	case "rdp":
		return drillRDP()
	case "vnc":
		return drillVNC()
	case "netbios":
		return drillNetbios()
	default:
		return fmt.Errorf("drill: unsupported service %q", args[0])
	}
}

func drillDialAddr(svc string) (string, error) {
	host, port, err := resolveProbeAddr(svc)
	if err != nil {
		return "", err
	}
	if port < 1 || port > 65535 {
		return "", fmt.Errorf("drill %s: invalid port %d", svc, port)
	}
	return net.JoinHostPort(host, strconv.Itoa(port)), nil
}

func drillFTP() error {
	addr, err := drillDialAddr("ftp")
	if err != nil {
		return err
	}
	line, err := tcpBanner(addr, "220")
	if err != nil {
		return exitErr(2, "drill ftp: %v", err)
	}
	fmt.Fprintf(os.Stderr, "amberctl: drill ftp OK (%s) banner=%q\n", addr, line)
	return nil
}

func drillSMTP() error {
	addr, err := drillDialAddr("smtp")
	if err != nil {
		return err
	}
	line, err := tcpBanner(addr, "220")
	if err != nil {
		return exitErr(2, "drill smtp: %v", err)
	}
	fmt.Fprintf(os.Stderr, "amberctl: drill smtp OK (%s) banner=%q\n", addr, line)
	return nil
}

func drillPOP3() error {
	addr, err := drillDialAddr("pop3")
	if err != nil {
		return err
	}
	line, err := tcpBanner(addr, "+OK")
	if err != nil {
		return exitErr(2, "drill pop3: %v", err)
	}
	fmt.Fprintf(os.Stderr, "amberctl: drill pop3 OK (%s) banner=%q\n", addr, line)
	return nil
}

func drillSSH() error {
	addr, err := drillDialAddr("ssh")
	if err != nil {
		return err
	}
	line, err := tcpBanner(addr, "SSH-")
	if err != nil {
		return exitErr(2, "drill ssh: %v", err)
	}
	fmt.Fprintf(os.Stderr, "amberctl: drill ssh OK (%s) banner=%q\n", addr, line)
	return nil
}

func drillRedis() error {
	addr, err := drillDialAddr("redis")
	if err != nil {
		return err
	}
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return exitErr(2, "drill redis: TCP connect to %s failed: %v", addr, err)
	}
	defer conn.Close()
	// RESP PING
	_, _ = conn.Write([]byte("*1\r\n$4\r\nPING\r\n"))
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 128)
	n, _ := conn.Read(buf)
	if n == 0 || !strings.Contains(string(buf[:n]), "PONG") {
		return exitErr(2, "drill redis: unexpected PING response from %s: %q", addr, string(buf[:n]))
	}
	fmt.Fprintf(os.Stderr, "amberctl: drill redis OK (%s) PING→PONG\n", addr)
	return nil
}

func drillHTTP() error {
	addr, err := drillDialAddr("http")
	if err != nil {
		return err
	}
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return exitErr(2, "drill http: TCP connect to %s failed: %v", addr, err)
	}
	defer conn.Close()
	_, _ = conn.Write([]byte("GET / HTTP/1.0\r\nHost: localhost\r\n\r\n"))
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 512)
	n, _ := conn.Read(buf)
	body := string(buf[:n])
	if n == 0 || (!strings.Contains(body, "HTTP/") && !strings.Contains(body, "html")) {
		return exitErr(2, "drill http: unexpected response from %s: %q", addr, truncate(body, 80))
	}
	fmt.Fprintf(os.Stderr, "amberctl: drill http OK (%s) preview=%q\n", addr, truncate(strings.TrimSpace(body), 80))
	return nil
}

func drillMySQL() error {
	addr, err := drillDialAddr("mysql")
	if err != nil {
		return err
	}
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return exitErr(2, "drill mysql: TCP connect to %s failed: %v", addr, err)
	}
	defer conn.Close()
	fmt.Fprintf(os.Stderr, "amberctl: drill mysql OK (%s) TCP connect\n", addr)
	return nil
}

func drillPostgres() error {
	addr, err := drillDialAddr("postgres")
	if err != nil {
		return err
	}
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return exitErr(2, "drill postgres: TCP connect to %s failed: %v", addr, err)
	}
	defer conn.Close()
	fmt.Fprintf(os.Stderr, "amberctl: drill postgres OK (%s) TCP connect\n", addr)
	return nil
}

func drillSMB() error {
	addr, err := drillDialAddr("smb")
	if err != nil {
		return err
	}
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return exitErr(2, "drill smb: TCP connect to %s failed: %v", addr, err)
	}
	defer conn.Close()
	fmt.Fprintf(os.Stderr, "amberctl: drill smb OK (%s) TCP connect\n", addr)
	return nil
}

func drillMongo() error {
	addr, err := drillDialAddr("mongo")
	if err != nil {
		return err
	}
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return exitErr(2, "drill mongo: TCP connect to %s failed: %v", addr, err)
	}
	defer conn.Close()
	fmt.Fprintf(os.Stderr, "amberctl: drill mongo OK (%s) TCP connect\n", addr)
	return nil
}

func drillDockerapi() error {
	addr, err := drillDialAddr("dockerapi")
	if err != nil {
		return err
	}
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return exitErr(2, "drill dockerapi: TCP connect to %s failed: %v", addr, err)
	}
	defer conn.Close()
	_, _ = conn.Write([]byte("GET /version HTTP/1.0\r\nHost: localhost\r\n\r\n"))
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 512)
	n, _ := conn.Read(buf)
	body := string(buf[:n])
	if n == 0 || !strings.Contains(body, "Docker") {
		return exitErr(2, "drill dockerapi: unexpected response from %s: %q", addr, truncate(body, 80))
	}
	fmt.Fprintf(os.Stderr, "amberctl: drill dockerapi OK (%s) Docker API trap banner\n", addr)
	return nil
}

func drillKubelet() error {
	addr, err := drillDialAddr("kubelet")
	if err != nil {
		return err
	}
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return exitErr(2, "drill kubelet: TCP connect to %s failed: %v", addr, err)
	}
	defer conn.Close()
	_, _ = conn.Write([]byte("GET /healthz HTTP/1.0\r\nHost: localhost\r\n\r\n"))
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 128)
	n, _ := conn.Read(buf)
	body := string(buf[:n])
	if n == 0 || !strings.Contains(body, "ok") {
		return exitErr(2, "drill kubelet: unexpected healthz from %s: %q", addr, truncate(body, 80))
	}
	fmt.Fprintf(os.Stderr, "amberctl: drill kubelet OK (%s) healthz=ok\n", addr)
	return nil
}

func drillOllama() error {
	addr, err := drillDialAddr("ollama")
	if err != nil {
		return err
	}
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return exitErr(2, "drill ollama: TCP connect to %s failed: %v", addr, err)
	}
	defer conn.Close()
	_, _ = conn.Write([]byte("GET /api/tags HTTP/1.0\r\nHost: localhost\r\n\r\n"))
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 512)
	n, _ := conn.Read(buf)
	body := string(buf[:n])
	if n == 0 || !strings.Contains(body, "models") {
		return exitErr(2, "drill ollama: unexpected /api/tags from %s: %q", addr, truncate(body, 80))
	}
	fmt.Fprintf(os.Stderr, "amberctl: drill ollama OK (%s) mock tags\n", addr)
	return nil
}

func drillElastic() error {
	addr, err := drillDialAddr("elastic")
	if err != nil {
		return err
	}
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return exitErr(2, "drill elastic: TCP connect to %s failed: %v", addr, err)
	}
	defer conn.Close()
	_, _ = conn.Write([]byte("GET / HTTP/1.0\r\nHost: localhost\r\n\r\n"))
	_ = conn.SetReadDeadline(time.Now().Add(8 * time.Second))
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	if n == 0 || !strings.Contains(string(buf[:n]), "HTTP/") {
		return exitErr(2, "drill elastic: unexpected response from %s", addr)
	}
	fmt.Fprintf(os.Stderr, "amberctl: drill elastic OK (%s)\n", addr)
	return nil
}

func drillMQTT() error {
	addr, err := drillDialAddr("mqtt")
	if err != nil {
		return err
	}
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return exitErr(2, "drill mqtt: TCP connect to %s failed: %v", addr, err)
	}
	defer conn.Close()
	fmt.Fprintf(os.Stderr, "amberctl: drill mqtt OK (%s) TCP connect\n", addr)
	return nil
}

// dnsUDPProbe sends a minimal A query for a lure-zone name present in every
// premade provider (www.ambercell.lab) and validates a DNS response (matching
// qid, QR bit, NOERROR). Shared by `amberctl drill dns` and the dns liveness
// probe. Apex ambercell.lab has no A in unbound local-data (NXDOMAIN), so the
// probe must use a record that all three providers answer.
func dnsUDPProbe(host string, port int) (string, error) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	const probeName = "www.ambercell.lab"
	qid := uint16(0x4143)
	query := buildDNSQuery(qid, probeName)
	conn, err := net.DialTimeout("udp", addr, 5*time.Second)
	if err != nil {
		return "", fmt.Errorf("UDP connect to %s failed: %w", addr, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(query); err != nil {
		return "", fmt.Errorf("send DNS query to %s failed: %w", addr, err)
	}
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		return "", fmt.Errorf("read DNS response from %s failed: %w", addr, err)
	}
	if n < 12 {
		return "", fmt.Errorf("short DNS response from %s (%d bytes)", addr, n)
	}
	respQid := uint16(buf[0])<<8 | uint16(buf[1])
	if respQid != qid {
		return "", fmt.Errorf("DNS response qid mismatch from %s", addr)
	}
	if buf[2]&0x80 == 0 {
		return "", fmt.Errorf("QR bit not set in response from %s", addr)
	}
	if rcode := buf[3] & 0x0F; rcode != 0 {
		return "", fmt.Errorf("DNS rcode %d from %s for %s", rcode, addr, probeName)
	}
	return fmt.Sprintf("A %s NOERROR %d bytes", probeName, n), nil
}

func buildDNSQuery(qid uint16, name string) []byte {
	b := make([]byte, 0, 12+2*len(name)+5)
	b = append(b, byte(qid>>8), byte(qid))
	b = append(b, 0x01, 0x00) // flags: RD=1
	b = append(b, 0x00, 0x01) // QDCOUNT=1
	b = append(b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	for _, label := range strings.Split(name, ".") {
		if label == "" {
			continue
		}
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	b = append(b, 0x00)
	b = append(b, 0x00, 0x01) // QTYPE=A
	b = append(b, 0x00, 0x01) // QCLASS=IN
	return b
}

func drillDNS() error {
	host, port, err := resolveProbeAddr("dns")
	if err != nil {
		return err
	}
	detail, err := dnsUDPProbe(host, port)
	if err != nil {
		return exitErr(2, "drill dns: %v", err)
	}
	fmt.Fprintf(os.Stderr, "amberctl: drill dns OK (%s) %s\n",
		net.JoinHostPort(host, strconv.Itoa(port)), detail)
	return nil
}

func drillTelnet() error {
	addr, err := drillDialAddr("telnet")
	if err != nil {
		return err
	}
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return exitErr(2, "drill telnet: TCP connect to %s failed: %v", addr, err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil && n == 0 {
		return exitErr(2, "drill telnet: read from %s failed: %v", addr, err)
	}
	snippet := strings.TrimSpace(string(buf[:n]))
	// Telnet may send IAC negotiation first; accept any non-empty read as liveness.
	if snippet == "" && n == 0 {
		return exitErr(2, "drill telnet: empty response from %s", addr)
	}
	fmt.Fprintf(os.Stderr, "amberctl: drill telnet OK (%s) bytes=%d preview=%q\n", addr, n, truncate(snippet, 80))
	return nil
}

func tcpBanner(addr, prefix string) (string, error) {
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return "", fmt.Errorf("TCP connect to %s failed: %w", addr, err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("read banner from %s failed: %w", addr, err)
	}
	line = strings.TrimSpace(line)
	if prefix != "" && !strings.HasPrefix(line, prefix) {
		return "", fmt.Errorf("unexpected banner from %s: %q", addr, line)
	}
	return line, nil
}

func envOr(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
