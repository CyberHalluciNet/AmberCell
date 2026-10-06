// SPDX-License-Identifier: LicenseRef-AmberCell-PSL-1.0

package compose

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveHiPrecedence(t *testing.T) {
	spec := Cells["ftp"]
	t.Setenv(spec.ProviderEnv, "vsftpd")
	_ = os.Unsetenv(spec.HiImageEnv())
	_ = os.Unsetenv(spec.ProviderContextEnv())

	r := ResolveHi(spec)
	if r.SkipHiBuild || r.Context != "services/ftp/providers/vsftpd" {
		t.Fatalf("builtin: %+v", r)
	}
	if r.Image != "ambercell-ftp-hi-vsftpd:local" {
		t.Fatalf("builtin image: %s", r.Image)
	}

	t.Setenv(spec.ProviderContextEnv(), "/tmp/my-ftp")
	t.Setenv(spec.ProviderEnv, "custom")
	r = ResolveHi(spec)
	if r.SkipHiBuild || r.Context != "/tmp/my-ftp" || r.Provider != "custom" {
		t.Fatalf("context: %+v", r)
	}
	if r.Image != "ambercell-ftp-hi-custom:local" {
		t.Fatalf("context image: %s", r.Image)
	}

	t.Setenv(spec.HiImageEnv(), "registry.example/ftp@sha256:abc")
	_ = os.Unsetenv(spec.ProviderContextEnv())
	r = ResolveHi(spec)
	if !r.SkipHiBuild || r.Image != "registry.example/ftp@sha256:abc" {
		t.Fatalf("hi_image: %+v", r)
	}
	// Custom provider_id must not invent a missing build context when HI_IMAGE wins.
	if r.Context != "services/ftp/providers/vsftpd" {
		t.Fatalf("hi_image fallback context: %s", r.Context)
	}
}

func TestResolveHiImageKeepsExplicitContext(t *testing.T) {
	spec := Cells["ftp"]
	t.Setenv(spec.ProviderEnv, "custom")
	t.Setenv(spec.HiImageEnv(), "registry.example/ftp:1")
	t.Setenv(spec.ProviderContextEnv(), "/opt/my-ftp")
	r := ResolveHi(spec)
	if !r.SkipHiBuild || r.Context != "/opt/my-ftp" {
		t.Fatalf("%+v", r)
	}
}

func TestValidateProviderContext(t *testing.T) {
	root := t.TempDir()
	ctx := filepath.Join(root, "svc")
	if err := os.MkdirAll(ctx, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := validateProviderContext(root, ctx); err == nil {
		t.Fatal("expected missing Dockerfile error")
	}
	if err := os.WriteFile(filepath.Join(ctx, "Dockerfile"), []byte("FROM scratch\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := validateProviderContext(root, ctx); err != nil {
		t.Fatal(err)
	}
	rel := "svc"
	if err := validateProviderContext(root, rel); err != nil {
		t.Fatal(err)
	}
}

func TestLoadProjectEnvShellWins(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, ".env")
	if err := os.WriteFile(path, []byte("AMBER_FTP_PROVIDER=fromfile\nAMBER_ONLY_FILE=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AMBER_FTP_PROVIDER", "fromshell")
	_ = os.Unsetenv("AMBER_ONLY_FILE")
	if err := LoadProjectEnv(root); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("AMBER_FTP_PROVIDER") != "fromshell" {
		t.Fatalf("shell should win: %s", os.Getenv("AMBER_FTP_PROVIDER"))
	}
	if os.Getenv("AMBER_ONLY_FILE") != "1" {
		t.Fatalf("file key missing: %s", os.Getenv("AMBER_ONLY_FILE"))
	}
}

func TestHiImageEnvNames(t *testing.T) {
	if Cells["ftp"].HiImageEnv() != "AMBER_FTP_HI_IMAGE" {
		t.Fatal(Cells["ftp"].HiImageEnv())
	}
	if Cells["dockerapi"].ProviderContextEnv() != "AMBER_DOCKERAPI_PROVIDER_CONTEXT" {
		t.Fatal(Cells["dockerapi"].ProviderContextEnv())
	}
}
