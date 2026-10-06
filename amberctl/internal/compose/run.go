// SPDX-License-Identifier: LicenseRef-AmberCell-PSL-1.0

package compose

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/CyberHalluciNet/AmberCell/amberctl/internal/paths"
)

const defaultProfiles = "lab,core"

// CellSpecs maps service name → compose service names + digests env + cell IP.
type CellSpec struct {
	Svc            string
	Collector      string
	Hi             string
	CollectorImage string
	HiImageFmt     string // printf with provider
	ProviderEnv    string
	DefaultProv    string
	HiDigestEnv    string
	CellIPEnv      string
	DefaultCellIP  string
	ExtraProfiles  []string // e.g. wave-a
}

var Cells = map[string]CellSpec{
	"ftp": {
		Svc:            "ftp",
		Collector:      "ftp-collector",
		Hi:             "ftp-hi",
		CollectorImage: "ambercell-ftp-collector:local",
		HiImageFmt:     "ambercell-ftp-hi-%s:local",
		ProviderEnv:    "AMBER_FTP_PROVIDER",
		DefaultProv:    "vsftpd",
		HiDigestEnv:    "AMBER_FTP_HI_DIGEST",
		CellIPEnv:      "AMBER_FTP_CELL_IP",
		DefaultCellIP:  "172.30.30.10",
	},
	"telnet": {
		Svc:            "telnet",
		Collector:      "telnet-collector",
		Hi:             "telnet-hi",
		CollectorImage: "ambercell-telnet-collector:local",
		HiImageFmt:     "ambercell-telnet-hi-%s:local",
		ProviderEnv:    "AMBER_TELNET_PROVIDER",
		DefaultProv:    "busybox-telnetd",
		HiDigestEnv:    "AMBER_TELNET_HI_DIGEST",
		CellIPEnv:      "AMBER_TELNET_CELL_IP",
		DefaultCellIP:  "172.30.40.10",
	},
	"smtp": {
		Svc:            "smtp",
		Collector:      "smtp-collector",
		Hi:             "smtp-hi",
		CollectorImage: "ambercell-smtp-collector:local",
		HiImageFmt:     "ambercell-smtp-hi-%s:local",
		ProviderEnv:    "AMBER_SMTP_PROVIDER",
		DefaultProv:    "postfix",
		HiDigestEnv:    "AMBER_SMTP_HI_DIGEST",
		CellIPEnv:      "AMBER_SMTP_CELL_IP",
		DefaultCellIP:  "172.30.10.10",
	},
	"pop3": {
		Svc:            "pop3",
		Collector:      "pop3-collector",
		Hi:             "pop3-hi",
		CollectorImage: "ambercell-pop3-collector:local",
		HiImageFmt:     "ambercell-pop3-hi-%s:local",
		ProviderEnv:    "AMBER_POP3_PROVIDER",
		DefaultProv:    "dovecot",
		HiDigestEnv:    "AMBER_POP3_HI_DIGEST",
		CellIPEnv:      "AMBER_POP3_CELL_IP",
		DefaultCellIP:  "172.30.20.10",
	},
	"ssh": {
		Svc:            "ssh",
		Collector:      "ssh-collector",
		Hi:             "ssh-hi",
		CollectorImage: "ambercell-ssh-collector:local",
		HiImageFmt:     "ambercell-ssh-hi-%s:local",
		ProviderEnv:    "AMBER_SSH_PROVIDER",
		DefaultProv:    "openssh",
		HiDigestEnv:    "AMBER_SSH_HI_DIGEST",
		CellIPEnv:      "AMBER_SSH_CELL_IP",
		DefaultCellIP:  "172.30.50.10",
		ExtraProfiles:  []string{"wave-a"},
	},
	"redis": {
		Svc:            "redis",
		Collector:      "redis-collector",
		Hi:             "redis-hi",
		CollectorImage: "ambercell-redis-collector:local",
		HiImageFmt:     "ambercell-redis-hi-%s:local",
		ProviderEnv:    "AMBER_REDIS_PROVIDER",
		DefaultProv:    "redis-server",
		HiDigestEnv:    "AMBER_REDIS_HI_DIGEST",
		CellIPEnv:      "AMBER_REDIS_CELL_IP",
		DefaultCellIP:  "172.30.60.10",
		ExtraProfiles:  []string{"wave-a"},
	},
	"mqtt": {
		Svc:            "mqtt",
		Collector:      "mqtt-collector",
		Hi:             "mqtt-hi",
		CollectorImage: "ambercell-mqtt-collector:local",
		HiImageFmt:     "ambercell-mqtt-hi-%s:local",
		ProviderEnv:    "AMBER_MQTT_PROVIDER",
		DefaultProv:    "mosquitto",
		HiDigestEnv:    "AMBER_MQTT_HI_DIGEST",
		CellIPEnv:      "AMBER_MQTT_CELL_IP",
		DefaultCellIP:  "172.30.70.10",
		ExtraProfiles:  []string{"wave-a"},
	},
	"http": {
		Svc:            "http",
		Collector:      "http-collector",
		Hi:             "http-hi",
		CollectorImage: "ambercell-http-collector:local",
		HiImageFmt:     "ambercell-http-hi-%s:local",
		ProviderEnv:    "AMBER_HTTP_PROVIDER",
		DefaultProv:    "nginx",
		HiDigestEnv:    "AMBER_HTTP_HI_DIGEST",
		CellIPEnv:      "AMBER_HTTP_CELL_IP",
		DefaultCellIP:  "172.30.80.10",
		ExtraProfiles:  []string{"wave-b"},
	},
	"mysql": {
		Svc:            "mysql",
		Collector:      "mysql-collector",
		Hi:             "mysql-hi",
		CollectorImage: "ambercell-mysql-collector:local",
		HiImageFmt:     "ambercell-mysql-hi-%s:local",
		ProviderEnv:    "AMBER_MYSQL_PROVIDER",
		DefaultProv:    "mariadb",
		HiDigestEnv:    "AMBER_MYSQL_HI_DIGEST",
		CellIPEnv:      "AMBER_MYSQL_CELL_IP",
		DefaultCellIP:  "172.30.90.10",
		ExtraProfiles:  []string{"wave-b"},
	},
	"postgres": {
		Svc:            "postgres",
		Collector:      "postgres-collector",
		Hi:             "postgres-hi",
		CollectorImage: "ambercell-postgres-collector:local",
		HiImageFmt:     "ambercell-postgres-hi-%s:local",
		ProviderEnv:    "AMBER_POSTGRES_PROVIDER",
		DefaultProv:    "postgresql",
		HiDigestEnv:    "AMBER_POSTGRES_HI_DIGEST",
		CellIPEnv:      "AMBER_POSTGRES_CELL_IP",
		DefaultCellIP:  "172.30.100.10",
		ExtraProfiles:  []string{"wave-b"},
	},
	"smb": {
		Svc:            "smb",
		Collector:      "smb-collector",
		Hi:             "smb-hi",
		CollectorImage: "ambercell-smb-collector:local",
		HiImageFmt:     "ambercell-smb-hi-%s:local",
		ProviderEnv:    "AMBER_SMB_PROVIDER",
		DefaultProv:    "samba",
		HiDigestEnv:    "AMBER_SMB_HI_DIGEST",
		CellIPEnv:      "AMBER_SMB_CELL_IP",
		DefaultCellIP:  "172.30.110.10",
		ExtraProfiles:  []string{"wave-c"},
	},
	"mongo": {
		Svc:            "mongo",
		Collector:      "mongo-collector",
		Hi:             "mongo-hi",
		CollectorImage: "ambercell-mongo-collector:local",
		HiImageFmt:     "ambercell-mongo-hi-%s:local",
		ProviderEnv:    "AMBER_MONGO_PROVIDER",
		DefaultProv:    "mongodb",
		HiDigestEnv:    "AMBER_MONGO_HI_DIGEST",
		CellIPEnv:      "AMBER_MONGO_CELL_IP",
		DefaultCellIP:  "172.30.120.10",
		ExtraProfiles:  []string{"wave-c"},
	},
	"elastic": {
		Svc:            "elastic",
		Collector:      "elastic-collector",
		Hi:             "elastic-hi",
		CollectorImage: "ambercell-elastic-collector:local",
		HiImageFmt:     "ambercell-elastic-hi-%s:local",
		ProviderEnv:    "AMBER_ELASTIC_PROVIDER",
		DefaultProv:    "elasticsearch",
		HiDigestEnv:    "AMBER_ELASTIC_HI_DIGEST",
		CellIPEnv:      "AMBER_ELASTIC_CELL_IP",
		DefaultCellIP:  "172.30.130.10",
		ExtraProfiles:  []string{"wave-c"},
	},
	"dockerapi": {
		Svc:            "dockerapi",
		Collector:      "dockerapi-collector",
		Hi:             "dockerapi-hi",
		CollectorImage: "ambercell-dockerapi-collector:local",
		HiImageFmt:     "ambercell-dockerapi-hi-%s:local",
		ProviderEnv:    "AMBER_DOCKERAPI_PROVIDER",
		DefaultProv:    "trap",
		HiDigestEnv:    "AMBER_DOCKERAPI_HI_DIGEST",
		CellIPEnv:      "AMBER_DOCKERAPI_CELL_IP",
		DefaultCellIP:  "172.30.140.10",
		ExtraProfiles:  []string{"wave-d"},
	},
	"kubelet": {
		Svc:            "kubelet",
		Collector:      "kubelet-collector",
		Hi:             "kubelet-hi",
		CollectorImage: "ambercell-kubelet-collector:local",
		HiImageFmt:     "ambercell-kubelet-hi-%s:local",
		ProviderEnv:    "AMBER_KUBELET_PROVIDER",
		DefaultProv:    "trap",
		HiDigestEnv:    "AMBER_KUBELET_HI_DIGEST",
		CellIPEnv:      "AMBER_KUBELET_CELL_IP",
		DefaultCellIP:  "172.30.150.10",
		ExtraProfiles:  []string{"wave-d"},
	},
	"ollama": {
		Svc:            "ollama",
		Collector:      "ollama-collector",
		Hi:             "ollama-hi",
		CollectorImage: "ambercell-ollama-collector:local",
		HiImageFmt:     "ambercell-ollama-hi-%s:local",
		ProviderEnv:    "AMBER_OLLAMA_PROVIDER",
		DefaultProv:    "mock",
		HiDigestEnv:    "AMBER_OLLAMA_HI_DIGEST",
		CellIPEnv:      "AMBER_OLLAMA_CELL_IP",
		DefaultCellIP:  "172.30.160.10",
		ExtraProfiles:  []string{"wave-e"},
	},
}

// LogInvokerUID writes uid to stderr for lifecycle auditing.
func LogInvokerUID(action string) {
	fmt.Fprintf(os.Stderr, "amberctl: %s invoked by uid=%d\n", action, os.Getuid())
}

func mergeProfiles(base string, extras ...string) string {
	seen := map[string]bool{}
	var out []string
	add := func(p string) {
		p = strings.TrimSpace(p)
		if p == "" || seen[p] {
			return
		}
		seen[p] = true
		out = append(out, p)
	}
	for _, p := range strings.Split(base, ",") {
		add(p)
	}
	for _, p := range extras {
		add(p)
	}
	return strings.Join(out, ",")
}

func composeEnv(extra ...string) []string {
	env := os.Environ()
	if os.Getenv("COMPOSE_PROFILES") == "" {
		env = append(env, "COMPOSE_PROFILES="+defaultProfiles)
	}
	return append(env, extra...)
}

func composeEnvForCell(spec CellSpec, extra ...string) []string {
	profiles := os.Getenv("COMPOSE_PROFILES")
	if profiles == "" {
		profiles = defaultProfiles
	}
	if len(spec.ExtraProfiles) > 0 {
		profiles = mergeProfiles(profiles, spec.ExtraProfiles...)
	}
	env := os.Environ()
	replaced := false
	for i, e := range env {
		if strings.HasPrefix(e, "COMPOSE_PROFILES=") {
			env[i] = "COMPOSE_PROFILES=" + profiles
			replaced = true
			break
		}
	}
	if !replaced {
		env = append(env, "COMPOSE_PROFILES="+profiles)
	}
	return append(env, extra...)
}

func useLabOverlay() bool {
	profiles := os.Getenv("COMPOSE_PROFILES")
	if profiles == "" {
		profiles = defaultProfiles
	}
	for _, p := range strings.Split(profiles, ",") {
		if strings.TrimSpace(p) == "lab" {
			return true
		}
	}
	return false
}

func useContainmentOverlay() bool {
	if os.Getenv("AMBER_ENFORCE_CONTAINMENT") == "1" {
		return true
	}
	profiles := os.Getenv("COMPOSE_PROFILES")
	for _, p := range strings.Split(profiles, ",") {
		if strings.TrimSpace(p) == "production" {
			return os.Getenv("AMBER_SKIP_CONTAINMENT") != "1"
		}
	}
	return false
}

func useLabExposeOverlay() bool {
	v := strings.TrimSpace(os.Getenv("AMBER_LAB_EXPOSE"))
	return v == "1" || strings.EqualFold(v, "true") || strings.EqualFold(v, "yes")
}

func composeFileArgs() []string {
	args := []string{"compose", "-f", "compose.yaml"}
	if useLabOverlay() {
		args = append(args, "-f", "compose.lab.yaml")
		if useLabExposeOverlay() {
			args = append(args, "-f", "compose.lab.expose.yaml")
		}
	}
	if useContainmentOverlay() {
		args = append(args, "-f", "compose.containment.yaml")
	}
	return args
}

func composeCmd(root string, args ...string) *exec.Cmd {
	cmd := exec.Command("docker", append(composeFileArgs(), args...)...)
	cmd.Dir = root
	cmd.Env = composeEnv()
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	return cmd
}

// BuildCollectorBase builds ambercell-collector-base:latest.
func BuildCollectorBase(root string) error {
	cmd := exec.Command(
		"docker", "build",
		"-t", "ambercell-collector-base:latest",
		"-f", "collectors/base/Dockerfile",
		".",
	)
	cmd.Dir = root
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func imageIDOrDigest(ref string) (string, error) {
	cmd := exec.Command("docker", "image", "inspect", "--format", "{{.Id}}", ref)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return "", err
	}
	id := strings.TrimSpace(out.String())
	if id == "" {
		return "", fmt.Errorf("empty image id for %s", ref)
	}
	return id, nil
}

func providerFor(spec CellSpec) string {
	if p := os.Getenv(spec.ProviderEnv); p != "" {
		return p
	}
	return spec.DefaultProv
}

func CellIP(svc string) string {
	spec, ok := Cells[svc]
	if !ok {
		return ""
	}
	if v := os.Getenv(spec.CellIPEnv); v != "" {
		return v
	}
	return spec.DefaultCellIP
}

// UpCell builds images, records digests, starts collector+hi (+ dns-sinkhole for core).
func UpCell(svc string) error {
	spec, ok := Cells[svc]
	if !ok {
		return fmt.Errorf("unknown service %q", svc)
	}
	root, err := paths.FindComposeRoot()
	if err != nil {
		return err
	}
	LogInvokerUID("up " + svc)
	if err := BuildCollectorBase(root); err != nil {
		return fmt.Errorf("build collector base: %w", err)
	}
	// Build cell + DNS sinkhole with the cell's wave profiles merged in.
	build := composeCmd(root, "build", spec.Collector, spec.Hi, "dns-sinkhole")
	build.Env = composeEnvForCell(spec)
	if err := build.Run(); err != nil {
		return err
	}

	prov := providerFor(spec)
	collDigest, err := imageIDOrDigest(spec.CollectorImage)
	if err != nil {
		return fmt.Errorf("inspect collector image: %w", err)
	}
	hiDigest, err := imageIDOrDigest(fmt.Sprintf(spec.HiImageFmt, prov))
	if err != nil {
		return fmt.Errorf("inspect hi image: %w", err)
	}
	fmt.Fprintf(os.Stderr, "amberctl: collector digest %s\n", collDigest)
	fmt.Fprintf(os.Stderr, "amberctl: hi digest %s\n", hiDigest)

	services := []string{spec.Collector, spec.Hi, "dns-sinkhole"}
	cmd := composeCmd(root, append([]string{"up", "-d", "--no-build"}, services...)...)
	cmd.Env = composeEnvForCell(
		spec,
		"AMBER_IMAGE_DIGEST="+collDigest,
		spec.HiDigestEnv+"="+hiDigest,
	)
	return cmd.Run()
}

// StopHI stops the hi sidecar (hi-first teardown order).
func StopHI(svc string) error {
	spec, ok := Cells[svc]
	if !ok {
		return fmt.Errorf("unknown service %q", svc)
	}
	root, err := paths.FindComposeRoot()
	if err != nil {
		return err
	}
	if err := composeCmd(root, "stop", spec.Hi).Run(); err != nil {
		return fmt.Errorf("stop %s: %w", spec.Hi, err)
	}
	return nil
}

// StopCollector stops the collector service.
func StopCollector(svc string) error {
	spec, ok := Cells[svc]
	if !ok {
		return fmt.Errorf("unknown service %q", svc)
	}
	root, err := paths.FindComposeRoot()
	if err != nil {
		return err
	}
	if err := composeCmd(root, "stop", spec.Collector).Run(); err != nil {
		return fmt.Errorf("stop %s: %w", spec.Collector, err)
	}
	return nil
}

// DownCell stops hi first, waits, then collector.
func DownCell(svc string) error {
	LogInvokerUID("down " + svc)
	if err := StopHI(svc); err != nil {
		return err
	}
	time.Sleep(5 * time.Second)
	return StopCollector(svc)
}

// Logs tails compose service logs (all core cells when svc is empty).
func Logs(svc string, stdout, stderr *os.File) error {
	root, err := paths.FindComposeRoot()
	if err != nil {
		return err
	}
	services := []string{}
	if svc == "" {
		for name := range Cells {
			spec := Cells[name]
			services = append(services, spec.Collector, spec.Hi)
		}
		services = append(services, "dns-sinkhole")
	} else {
		spec, ok := Cells[svc]
		if !ok {
			return fmt.Errorf("unknown service %q", svc)
		}
		services = []string{spec.Collector, spec.Hi}
	}
	cmd := composeCmd(root, append([]string{"logs", "-f", "--tail=100"}, services...)...)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	return cmd.Run()
}

// PS runs docker compose ps for the ambercell project.
func PS() error {
	root, err := paths.FindComposeRoot()
	if err != nil {
		return err
	}
	return composeCmd(root, "ps").Run()
}

// Legacy aliases for Stage-0B call sites.
func UpFTP() error             { return UpCell("ftp") }
func StopFTPHI() error         { return StopHI("ftp") }
func StopFTPCollector() error  { return StopCollector("ftp") }
func DownFTP() error           { return DownCell("ftp") }
