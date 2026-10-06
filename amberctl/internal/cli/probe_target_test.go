// SPDX-License-Identifier: LicenseRef-AmberCell-PSL-1.0

package cli

import (
	"os"
	"testing"
)

func TestResolveProbeAddrLabDefaults(t *testing.T) {
	t.Setenv("COMPOSE_PROFILES", "lab,core")
	t.Setenv("AMBER_TELNET_DRILL_HOST", "")
	t.Setenv("AMBER_TELNET_HOST_PORT", "")
	host, port, err := resolveProbeAddr("telnet")
	if err != nil {
		t.Fatal(err)
	}
	if host != "127.0.0.1" || port != 2323 {
		t.Fatalf("lab telnet got %s:%d want 127.0.0.1:2323", host, port)
	}
}

func TestResolveProbeAddrProductionUsesCellIP(t *testing.T) {
	t.Setenv("COMPOSE_PROFILES", "production,core")
	t.Setenv("AMBER_PROFILE", "production")
	for _, k := range []string{
		"AMBER_FTP_DRILL_HOST", "AMBER_FTP_HOST_PORT",
		"AMBER_TELNET_DRILL_HOST", "AMBER_TELNET_HOST_PORT",
	} {
		_ = os.Unsetenv(k)
	}
	host, port, err := resolveProbeAddr("ftp")
	if err != nil {
		t.Fatal(err)
	}
	if host != "172.30.30.10" || port != 21 {
		t.Fatalf("production ftp got %s:%d want 172.30.30.10:21", host, port)
	}
	host, port, err = resolveProbeAddr("telnet")
	if err != nil {
		t.Fatal(err)
	}
	if host != "172.30.40.10" || port != 23 {
		t.Fatalf("production telnet got %s:%d want 172.30.40.10:23", host, port)
	}
}

func TestEnsureProductionPasv(t *testing.T) {
	t.Setenv("COMPOSE_PROFILES", "production,core")
	_ = os.Unsetenv("AMBER_FTP_PASV_ADDRESS")
	if err := ensureProductionPasv("ftp"); err == nil {
		t.Fatal("expected error when PASV unset")
	}
	t.Setenv("AMBER_FTP_PASV_ADDRESS", "127.0.0.1")
	if err := ensureProductionPasv("ftp"); err == nil {
		t.Fatal("expected error for 127.0.0.1")
	}
	t.Setenv("AMBER_FTP_PASV_ADDRESS", "203.0.113.10")
	if err := ensureProductionPasv("ftp"); err != nil {
		t.Fatal(err)
	}
	if err := ensureProductionPasv("telnet"); err != nil {
		t.Fatal(err)
	}
}
