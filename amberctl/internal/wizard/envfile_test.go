// SPDX-License-Identifier: LicenseRef-AmberCell-PSL-1.0

package wizard

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMergeEnvFilePreservesUnrelated(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	if err := os.WriteFile(path, []byte("KEEP=1\nAMBER_FTP_PROVIDER=vsftpd\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := MergeEnvFile(path, map[string]string{
		"AMBER_FTP_PROVIDER": "custom",
		"AMBER_FTP_HI_IMAGE": "img@sha256:1",
	}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	if !strings.Contains(s, "KEEP=1") {
		t.Fatalf("lost unrelated key: %s", s)
	}
	if !strings.Contains(s, "AMBER_FTP_PROVIDER=custom") {
		t.Fatalf("provider not updated: %s", s)
	}
	if !strings.Contains(s, "AMBER_FTP_HI_IMAGE=img@sha256:1") {
		t.Fatalf("hi image not appended: %s", s)
	}
}

func TestMergeEnvFileCreates0600(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	if err := MergeEnvFile(path, map[string]string{"AMBER_FTP_PROVIDER": "vsftpd"}); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o want 0600", st.Mode().Perm())
	}
}

func TestMergeEnvFileRejectsNewlineValue(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	err := MergeEnvFile(path, map[string]string{
		"AMBER_FTP_HI_IMAGE": "img\nAMBER_INJECTED=1",
	})
	if err == nil {
		t.Fatal("expected newline rejection")
	}
}

func TestMergeEnvAllowClearRemovesKeys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	if err := os.WriteFile(path, []byte(
		"AMBER_FTP_PROVIDER=vsftpd\nAMBER_FTP_HI_IMAGE=old\nAMBER_FTP_PROVIDER_CONTEXT=/tmp/x\nKEEP=1\n",
	), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := mergeEnvAllowClear(path, map[string]string{
		"AMBER_FTP_PROVIDER":         "proftpd",
		"AMBER_FTP_HI_IMAGE":         "",
		"AMBER_FTP_PROVIDER_CONTEXT": "",
	}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	if !strings.Contains(s, "AMBER_FTP_PROVIDER=proftpd") || !strings.Contains(s, "KEEP=1") {
		t.Fatalf("unexpected: %s", s)
	}
	if strings.Contains(s, "AMBER_FTP_HI_IMAGE") || strings.Contains(s, "AMBER_FTP_PROVIDER_CONTEXT") {
		t.Fatalf("cleared keys still present: %s", s)
	}
}

func TestAvailableProvidersFiltersMissing(t *testing.T) {
	root := t.TempDir()
	mustMk := func(rel string) {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("FROM scratch\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mustMk("services/ftp/providers/vsftpd/Dockerfile")
	// proftpd directory exists but no Dockerfile
	if err := os.MkdirAll(filepath.Join(root, "services/ftp/providers/proftpd"), 0o755); err != nil {
		t.Fatal(err)
	}
	cell, ok := CellBySvc("ftp")
	if !ok {
		t.Fatal("ftp missing")
	}
	avail := AvailableProviders(root, cell)
	if len(avail) != 1 || avail[0].ID != "vsftpd" {
		t.Fatalf("got %+v", avail)
	}
}
