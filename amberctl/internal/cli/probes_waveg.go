// SPDX-License-Identifier: LicenseRef-AmberCell-PSL-1.0

package cli

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// Wave-G protocol probes: real request/response over UDP/TCP, shared by
// `amberctl drill` and liveness. Each returns a short success detail string.

// probeTFTP sends a RRQ for the seed README and expects any TFTP reply
// (DATA 0x0003, ERROR 0x0005, or OACK 0x0006) from the cell.
func probeTFTP(host string, port int) (string, error) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := net.DialTimeout("udp", addr, 5*time.Second)
	if err != nil {
		return "", fmt.Errorf("UDP connect to %s failed: %w", addr, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	rrq := []byte{0x00, 0x01}
	rrq = append(rrq, []byte("seed/README.txt")...)
	rrq = append(rrq, 0x00)
	rrq = append(rrq, []byte("octet")...)
	rrq = append(rrq, 0x00)
	if _, err := conn.Write(rrq); err != nil {
		return "", fmt.Errorf("send RRQ to %s failed: %w", addr, err)
	}
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		return "", fmt.Errorf("read TFTP reply from %s failed: %w", addr, err)
	}
	if n < 4 {
		return "", fmt.Errorf("short TFTP reply from %s (%d bytes)", addr, n)
	}
	op := binary.BigEndian.Uint16(buf[:2])
	switch op {
	case 0x0003, 0x0005, 0x0006:
		return fmt.Sprintf("RRQ reply opcode %d (%d bytes)", op, n), nil
	default:
		return "", fmt.Errorf("unexpected TFTP opcode %d from %s", op, addr)
	}
}

// probeSNMP sends a SNMPv2c GET for sysDescr.0 (community "public") and
// expects a GetResponse PDU (tag 0xa2).
func probeSNMP(host string, port int) (string, error) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	// sysDescr.0 = 1.3.6.1.2.1.1.1.0
	oid := []byte{0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00}
	varbind := append([]byte{0x30, byte(len(oid) + 4)}, 0x06, byte(len(oid)))
	varbind = append(varbind, oid...)
	varbind = append(varbind, 0x05, 0x00)
	vbl := []byte{0x30, byte(len(varbind))}
	vbl = append(vbl, varbind...)
	pdu := []byte{0xa0, byte(len(vbl) + 9), 0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00}
	pdu = append(pdu, vbl...)
	community := append([]byte{0x04, 0x06}, []byte("public")...)
	msg := append([]byte{0x30, byte(len(community) + len(pdu) + 3), 0x02, 0x01, 0x01}, community...)
	msg = append(msg, pdu...)

	conn, err := net.DialTimeout("udp", addr, 5*time.Second)
	if err != nil {
		return "", fmt.Errorf("UDP connect to %s failed: %w", addr, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(msg); err != nil {
		return "", fmt.Errorf("send SNMP GET to %s failed: %w", addr, err)
	}
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		return "", fmt.Errorf("read SNMP response from %s failed: %w", addr, err)
	}
	if n < 8 || buf[0] != 0x30 {
		return "", fmt.Errorf("malformed SNMP response from %s", addr)
	}
	for i := 0; i+1 < n; i++ {
		if buf[i] == 0xa2 {
			return fmt.Sprintf("GetResponse %d bytes", n), nil
		}
	}
	return "", fmt.Errorf("no GetResponse PDU in reply from %s", addr)
}

// probeNTP sends a v4 client packet and expects a server (mode 4) reply.
func probeNTP(host string, port int) (string, error) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := net.DialTimeout("udp", addr, 5*time.Second)
	if err != nil {
		return "", fmt.Errorf("UDP connect to %s failed: %w", addr, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	pkt := make([]byte, 48)
	pkt[0] = 0x23 // LI=0, VN=4, Mode=3 (client)
	pkt[1] = 0x00 // stratum 0
	if _, err := conn.Write(pkt); err != nil {
		return "", fmt.Errorf("send NTP request to %s failed: %w", addr, err)
	}
	buf := make([]byte, 48)
	n, err := conn.Read(buf)
	if err != nil {
		return "", fmt.Errorf("read NTP response from %s failed: %w", addr, err)
	}
	if n < 48 {
		return "", fmt.Errorf("short NTP response from %s (%d bytes)", addr, n)
	}
	mode := buf[0] & 0x07
	if mode != 4 {
		return "", fmt.Errorf("NTP reply mode %d from %s (want server mode 4)", mode, addr)
	}
	return fmt.Sprintf("server reply stratum %d", buf[1]), nil
}

// probeSyslog sends one RFC3164 line over TCP (fire-and-forget; connect+send
// is the drill — no reply is expected).
func probeSyslog(host string, port int) (string, error) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return "", fmt.Errorf("TCP connect to %s failed: %w", addr, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	line := "<142>ambercell-drill drill[1]: amberctl syslog drill\n"
	if _, err := conn.Write([]byte(line)); err != nil {
		return "", fmt.Errorf("send syslog line to %s failed: %w", addr, err)
	}
	return "line sent", nil
}

// probeSIP sends OPTIONS over TCP and expects a SIP/2.0 reply.
func probeSIP(host string, port int) (string, error) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return "", fmt.Errorf("TCP connect to %s failed: %w", addr, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	req := "OPTIONS sip:drill@ambercell.lab SIP/2.0\r\n" +
		"Via: SIP/2.0/TCP drill.ambercell.lab\r\n" +
		"From: <sip:drill@ambercell.lab>;tag=drill\r\n" +
		"To: <sip:drill@ambercell.lab>\r\n" +
		"Call-ID: drill@ambercell\r\n" +
		"CSeq: 1 OPTIONS\r\n" +
		"Content-Length: 0\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		return "", fmt.Errorf("send OPTIONS to %s failed: %w", addr, err)
	}
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		return "", fmt.Errorf("read SIP reply from %s failed: %w", addr, err)
	}
	reply := string(buf[:n])
	if !strings.HasPrefix(reply, "SIP/2.0") {
		return "", fmt.Errorf("unexpected SIP reply from %s: %q", addr, truncate(reply, 60))
	}
	return strings.Fields(reply)[0] + " " + strings.Fields(reply)[1], nil
}

// probeLDAP sends a minimal anonymous bind and expects an LDAP bind response
// (application tag 0x61) with a parseable result code.
func probeLDAP(host string, port int) (string, error) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return "", fmt.Errorf("TCP connect to %s failed: %w", addr, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	// bind(1) { version 3, name "", simple "" } — anonymous, no auth.
	bind := []byte{0x30, 0x0c, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02, 0x01, 0x03, 0x04, 0x00, 0x80, 0x00}
	if _, err := conn.Write(bind); err != nil {
		return "", fmt.Errorf("send LDAP bind to %s failed: %w", addr, err)
	}
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		return "", fmt.Errorf("read LDAP reply from %s failed: %w", addr, err)
	}
	if n < 7 || buf[0] != 0x30 {
		return "", fmt.Errorf("malformed LDAP reply from %s", addr)
	}
	for i := 0; i+1 < n; i++ {
		if buf[i] == 0x61 {
			return fmt.Sprintf("bind response %d bytes", n), nil
		}
	}
	return "", fmt.Errorf("no bind response PDU from %s", addr)
}

func drillTFTP() error {
	h, p, err := resolveProbeAddr("tftp")
	if err != nil {
		return err
	}
	detail, err := probeTFTP(h, p)
	if err != nil {
		return exitErr(2, "drill tftp: %v", err)
	}
	fmt.Fprintf(os.Stderr, "amberctl: drill tftp OK (%s) %s\n", net.JoinHostPort(h, strconv.Itoa(p)), detail)
	return nil
}

func drillSNMP() error {
	h, p, err := resolveProbeAddr("snmp")
	if err != nil {
		return err
	}
	detail, err := probeSNMP(h, p)
	if err != nil {
		return exitErr(2, "drill snmp: %v", err)
	}
	fmt.Fprintf(os.Stderr, "amberctl: drill snmp OK (%s) %s\n", net.JoinHostPort(h, strconv.Itoa(p)), detail)
	return nil
}

func drillNTP() error {
	h, p, err := resolveProbeAddr("ntp")
	if err != nil {
		return err
	}
	detail, err := probeNTP(h, p)
	if err != nil {
		return exitErr(2, "drill ntp: %v", err)
	}
	fmt.Fprintf(os.Stderr, "amberctl: drill ntp OK (%s) %s\n", net.JoinHostPort(h, strconv.Itoa(p)), detail)
	return nil
}

func drillSyslog() error {
	h, p, err := resolveProbeAddr("syslog")
	if err != nil {
		return err
	}
	detail, err := probeSyslog(h, p)
	if err != nil {
		return exitErr(2, "drill syslog: %v", err)
	}
	fmt.Fprintf(os.Stderr, "amberctl: drill syslog OK (%s) %s\n", net.JoinHostPort(h, strconv.Itoa(p)), detail)
	return nil
}

func drillSIP() error {
	h, p, err := resolveProbeAddr("sip")
	if err != nil {
		return err
	}
	detail, err := probeSIP(h, p)
	if err != nil {
		return exitErr(2, "drill sip: %v", err)
	}
	fmt.Fprintf(os.Stderr, "amberctl: drill sip OK (%s) %s\n", net.JoinHostPort(h, strconv.Itoa(p)), detail)
	return nil
}

func drillLDAP() error {
	h, p, err := resolveProbeAddr("ldap")
	if err != nil {
		return err
	}
	detail, err := probeLDAP(h, p)
	if err != nil {
		return exitErr(2, "drill ldap: %v", err)
	}
	fmt.Fprintf(os.Stderr, "amberctl: drill ldap OK (%s) %s\n", net.JoinHostPort(h, strconv.Itoa(p)), detail)
	return nil
}
