// SPDX-License-Identifier: LicenseRef-AmberCell-PSL-1.0

package cli

import (
	"fmt"
	"os"
)

// ExitError carries a process exit code for main.
type ExitError struct {
	Code    int
	Message string
}

func (e *ExitError) Error() string { return e.Message }

func exitErr(code int, format string, args ...any) error {
	return &ExitError{Code: code, Message: fmt.Sprintf(format, args...)}
}

// Run dispatches subcommands. Returns ExitError for controlled exits.
func Run(args []string) error {
	if len(args) == 0 {
		printUsage(os.Stdout)
		return nil
	}

	switch args[0] {
	case "init":
		return runInit(args[1:])
	case "up":
		return runUp(args[1:])
	case "down":
		return runDown(args[1:])
	case "status":
		return runStatus(args[1:])
	case "export":
		return runExport(args[1:])
	case "rebuild":
		return runRebuild(args[1:])
	case "reset":
		return runReset(args[1:])
	case "drill":
		return runDrill(args[1:])
	case "liveness":
		return runLiveness(args[1:])
	case "replay":
		return runReplay(args[1:])
	case "logs":
		return runLogs(args[1:])
	case "publish":
		return runPublish(args[1:])
	case "ai":
		return runAI(args[1:])
	case "critic":
		return runCritic(args[1:])
	case "execute-decision":
		return runExecuteDecision(args[1:])
	case "nft":
		return runNft(args[1:])
	case "-h", "--help", "help":
		printUsage(os.Stdout)
		return nil
	default:
		return fmt.Errorf("unknown command %q (try: init, up, down, status, logs, export, publish, drill, replay, ai, critic, liveness, nft)", args[0])
	}
}

func printUsage(w *os.File) {
	const cells = "ftp|telnet|smtp|pop3|ssh|redis|mqtt|http|mysql|postgres|smb|mongo|elastic|dockerapi|kubelet|ollama"
	fmt.Fprintf(w, `amberctl — AmberCell operator CLI (Stages 1–7)

Usage:
  amberctl init [--yes] [--wizard] [--cells ftp,smtp,…]
  amberctl up `+cells+`
  amberctl down `+cells+`
  amberctl status [--drift]
  amberctl logs [`+cells+`]
  amberctl export [-out DIR] [--live]
  amberctl publish [--class summary|full] [--pcap] [--svc SVC]
  amberctl replay [--diff] [--actual PATH] <golden.jsonl|case>
  amberctl ai decisions [--svc SVC] | ai approve ID | ai review [--svc SVC]
  amberctl critic --decision PATH
  amberctl drill `+cells+`
  amberctl reset `+cells+`
  amberctl rebuild `+cells+`
  amberctl liveness [--once] [`+cells+`]
  amberctl execute-decision --decision <action> [--svc `+cells+`]
  amberctl nft apply|status

Lifecycle commands log the invoking uid. rebuild/reset take an exclusive flock on
state/<svc>.lock (concurrent attempt exits 6). Rebuild cooldown: 15m gap, max 3/hour.
Liveness: TCP+banner every 30s; 3 fails → snapshot_then_rebuild (independent of AI).
Production (COMPOSE_PROFILES includes production): probes cell IPs on ambernet;
nft apply runs after up (AMBER_SKIP_NFT_APPLY=1 to skip).

Init: TTY runs the provider wizard (premade vs own Docker → .env). --yes or
AMBER_INIT_NONINTERACTIVE=1 skips prompts. --wizard forces the wizard (needs stdin).

Environment:
  AMBER_EVIDENCE_ROOT     evidence tree (default /var/ambercell; mode 0750 root:amber in prod)
  AMBER_ROOT              repo root with compose.yaml
  AMBER_INIT_NONINTERACTIVE=1  skip init wizard (same as init --yes)
  COMPOSE_PROFILES        docker compose profiles (default lab,core; production,core for prod)
  AMBER_ENFORCE_CONTAINMENT=1  also load compose.containment.yaml (seccomp/AppArmor)
  AMBER_FTP_PASV_ADDRESS  required public IPv4 in production (not 127.0.0.1)
  AMBER_SKIP_NFT_APPLY=1  skip automatic nft apply after production up
  AMBER_FORCE_NFT=1       run nft even on non-Linux (testing only)
  AMBER_FTP_HOST_PORT     drill/liveness FTP port (lab often 2121)
  AMBER_TELNET_HOST_PORT  drill/liveness Telnet port (lab default 2323)
  AMBER_SMTP_HOST_PORT    lab SMTP (default 2525)
  AMBER_POP3_HOST_PORT    lab POP3 (default 1110)
  AMBER_SSH_HOST_PORT     lab honeypot SSH (default 2222; not admin SSH — G9)
  AMBER_REDIS_HOST_PORT   lab Redis (default 6379)
  AMBER_MQTT_HOST_PORT    lab MQTT (default 1883)

`)
}

