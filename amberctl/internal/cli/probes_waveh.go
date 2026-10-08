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

// Wave-H protocol probes: IMAP banner, memcached version, RDP X.224
// negotiation, VNC RFB banner, and a NetBIOS name-service query.

func probeIMAP(host string, port int) (string, error) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	line, err := tcpBanner(addr, "* OK")
	if err != nil {
		return "", err
	}
	return truncate(line, 60), nil
}

func probeMemcached(host string, port int) (string, error) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return "", fmt.Errorf("TCP connect to %s failed: %w", addr, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte("version\r\n")); err != nil {
		return "", fmt.Errorf("send version to %s failed: %w", addr, err)
	}
	buf := make([]byte, 128)
	n, err := conn.Read(buf)
	if err != nil {
		return "", fmt.Errorf("read memcached reply from %s failed: %w", addr, err)
	}
	reply := strings.TrimSpace(string(buf[:n]))
	if !strings.HasPrefix(reply, "VERSION") {
		return "", fmt.Errorf("unexpected memcached reply from %s: %q", addr, truncate(reply, 40))
	}
	return reply, nil
}

// probeRDP sends an X.224 Class-0 connection request with a negotiation
// request (RDP neg header: PROTOCOL_RDP|PROTOCOL_SSL) and expects a TPKT
// response (first byte 0x03).
func probeRDP(host string, port int) (string, error) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return "", fmt.Errorf("TCP connect to %s failed: %w", addr, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	// TPKT(4) + X.224 CR TPDU(7) + RDP negotiation request(8)
	req := []byte{
		0x03, 0x00, 0x00, 0x13, // TPKT v3, length 19
		0x0e,                               // CR length
		0xe0,                               // CR TPDU code
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // dst/ref src-ref + class 0
		0x01, 0x00, // TYPE_RDP_NEG_REQ
		0x08, 0x00, // length 8
		0x03, 0x00, 0x00, 0x00, // requested protocols: 0x03 = PROTOCOL_SSL|PROTOCOL_HYBRID
	}
	if _, err := conn.Write(req); err != nil {
		return "", fmt.Errorf("send X.224 CR to %s failed: %w", addr, err)
	}
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		return "", fmt.Errorf("read RDP reply from %s failed: %w", addr, err)
	}
	if n < 4 || buf[0] != 0x03 {
		return "", fmt.Errorf("no TPKT response from %s: %x", addr, buf[:min(n, 8)])
	}
	selected := 0
	if n >= 15 && buf[11] == 0x02 { // TYPE_RDP_NEG_RSP
		selected = int(binary.BigEndian.Uint32(buf[15:19]))
	}
	return fmt.Sprintf("TPKT X.224 response (%d bytes, neg 0x%x)", n, selected), nil
}

func probeVNC(host string, port int) (string, error) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	line, err := tcpBanner(addr, "RFB")
	if err != nil {
		return "", err
	}
	return truncate(line, 32), nil
}

// probeNetbios sends an NBNS name query for FILESRV01<00> and expects a
// response (any answer or RCODE name-error — both prove the daemon answered).
func probeNetbios(host string, port int) (string, error) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	var q bytesBuffer
	q.write16(0x8100) // tid
	q.write16(0x0000) // flags: 0 — nmbd drops unicast NBNS queries with RD set
	q.write16(0x0001) // QDCOUNT
	q.write16(0x0000) // ANCOUNT
	q.write16(0x0000) // NSCOUNT
	q.write16(0x0000) // ARCOUNT
	// first-level encoded "FILESRV01<00>" padded to 15 chars; NBNS names are
	// DNS-style length-prefixed labels (0x20 = 32 encoded bytes).
	q.buf = append(q.buf, 0x20)
	raw := []byte("FILESRV01")
	for i := 0; i < 15; i++ {
		b := byte(' ')
		if i < len(raw) {
			b = raw[i]
		}
		q.buf = append(q.buf, 'A'+(b>>4), 'A'+(b&0xF))
	}
	suffix := byte(0x00)
	q.buf = append(q.buf, 'A'+(suffix>>4), 'A'+(suffix&0xF))
	q.buf = append(q.buf, 0x00) // name terminator
	q.write16(0x0020)           // NB
	q.write16(0x0001)           // IN

	conn, err := net.DialTimeout("udp", addr, 5*time.Second)
	if err != nil {
		return "", fmt.Errorf("UDP connect to %s failed: %w", addr, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(q.buf); err != nil {
		return "", fmt.Errorf("send NBNS query to %s failed: %w", addr, err)
	}
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		return "", fmt.Errorf("read NBNS response from %s failed: %w", addr, err)
	}
	if n < 12 || binary.BigEndian.Uint16(buf[0:2]) != 0x8100 {
		return "", fmt.Errorf("unexpected NBNS response from %s", addr)
	}
	flags := binary.BigEndian.Uint16(buf[2:4])
	answers := binary.BigEndian.Uint16(buf[6:8])
	return fmt.Sprintf("NBNS response flags 0x%04x answers %d", flags, answers), nil
}

type bytesBuffer struct{ buf []byte }

func (b *bytesBuffer) write16(v uint16) {
	b.buf = append(b.buf, byte(v>>8), byte(v))
}

func drillIMAP() error {
	h, p, err := resolveProbeAddr("imap")
	if err != nil {
		return err
	}
	detail, err := probeIMAP(h, p)
	if err != nil {
		return exitErr(2, "drill imap: %v", err)
	}
	fmt.Fprintf(os.Stderr, "amberctl: drill imap OK (%s) %s\n", net.JoinHostPort(h, strconv.Itoa(p)), detail)
	return nil
}

func drillMemcached() error {
	h, p, err := resolveProbeAddr("memcached")
	if err != nil {
		return err
	}
	detail, err := probeMemcached(h, p)
	if err != nil {
		return exitErr(2, "drill memcached: %v", err)
	}
	fmt.Fprintf(os.Stderr, "amberctl: drill memcached OK (%s) %s\n", net.JoinHostPort(h, strconv.Itoa(p)), detail)
	return nil
}

func drillRDP() error {
	h, p, err := resolveProbeAddr("rdp")
	if err != nil {
		return err
	}
	detail, err := probeRDP(h, p)
	if err != nil {
		return exitErr(2, "drill rdp: %v", err)
	}
	fmt.Fprintf(os.Stderr, "amberctl: drill rdp OK (%s) %s\n", net.JoinHostPort(h, strconv.Itoa(p)), detail)
	return nil
}

func drillVNC() error {
	h, p, err := resolveProbeAddr("vnc")
	if err != nil {
		return err
	}
	detail, err := probeVNC(h, p)
	if err != nil {
		return exitErr(2, "drill vnc: %v", err)
	}
	fmt.Fprintf(os.Stderr, "amberctl: drill vnc OK (%s) %s\n", net.JoinHostPort(h, strconv.Itoa(p)), detail)
	return nil
}

func drillNetbios() error {
	h, p, err := resolveProbeAddr("netbios")
	if err != nil {
		return err
	}
	detail, err := probeNetbios(h, p)
	if err != nil {
		return exitErr(2, "drill netbios: %v", err)
	}
	fmt.Fprintf(os.Stderr, "amberctl: drill netbios OK (%s) %s\n", net.JoinHostPort(h, strconv.Itoa(p)), detail)
	return nil
}
