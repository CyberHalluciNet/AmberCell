// SPDX-License-Identifier: LicenseRef-AmberCell-PSL-1.0

package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/CyberHalluciNet/AmberCell/amberctl/internal/compose"
	"github.com/CyberHalluciNet/AmberCell/amberctl/internal/cooldown"
	"github.com/CyberHalluciNet/AmberCell/amberctl/internal/nftables"
	"github.com/CyberHalluciNet/AmberCell/amberctl/internal/paths"
	"github.com/CyberHalluciNet/AmberCell/amberctl/internal/webhook"
)

// Guardrail FSM for AI/executor remediation decisions.
// States: idle → pending → executing → cooldown | quarantined
// Bounded actions only; never silent drop of rejected commands.

type fsmState string

const (
	fsmIdle        fsmState = "idle"
	fsmPending     fsmState = "pending"
	fsmExecuting   fsmState = "executing"
	fsmCooldown    fsmState = "cooldown"
	fsmQuarantined fsmState = "quarantined"
)

func runExecuteDecision(args []string) error {
	fsDecision := ""
	fsSvc := "ftp"
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--decision" && i+1 < len(args):
			i++
			fsDecision = args[i]
		case a == "--svc" && i+1 < len(args):
			i++
			fsSvc = args[i]
		case !strings.HasPrefix(a, "-") && fsDecision == "":
			fsDecision = a
		}
	}
	d := strings.TrimSpace(fsDecision)
	if d == "" {
		return fmt.Errorf("execute-decision: --decision or positional action required")
	}
	if !supportedCell(fsSvc) {
		return fmt.Errorf("execute-decision: unsupported svc %q", fsSvc)
	}

	switch d {
	case "annotate", "suppress":
		fmt.Fprintf(os.Stderr, "amberctl: execute-decision %s → %s (no mutation; recorded)\n", d, fsSvc)
		return nil
	case "alert":
		fmt.Fprintf(os.Stderr, "amberctl: execute-decision alert → %s (async webhook; never blocks rebuild)\n", fsSvc)
		webhook.Default().EnqueueAndTryDeliver(webhook.Alert{
			AlertID:    fmt.Sprintf("alert-%s-%d", fsSvc, time.Now().UnixNano()),
			Kind:       "decision_alert",
			Svc:        fsSvc,
			Summary:    "AI manager alert for " + fsSvc,
			DecisionID: os.Getenv("AMBER_DECISION_ID"),
			SessionID:  os.Getenv("AMBER_SESSION_ID"),
		})
		return nil
	case "snapshot_then_rebuild":
		if err := runDecisionCriticFile(os.Getenv("AMBER_DECISION_FILE")); err != nil {
			return err
		}
		if err := cooldown.CheckRebuild(fsSvc); err != nil {
			fmt.Fprintf(os.Stderr, "amberctl: FSM %s → %s (rebuild rejected)\n", fsmCooldown, err)
			return exitErr(5, "execute-decision: %v", err)
		}
		fmt.Fprintf(os.Stderr, "amberctl: FSM %s → %s for %s\n", fsmPending, fsmExecuting, fsSvc)
		return withLifecycleLock(fsSvc, "execute-decision", func() error {
			if err := rebuildCell(fsSvc); err != nil {
				return err
			}
			_ = cooldown.RecordRebuild(fsSvc)
			return nil
		})
	case "quarantine_then_rebuild":
		if err := runDecisionCriticFile(os.Getenv("AMBER_DECISION_FILE")); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "amberctl: FSM → %s for %s (nft set amber_quarantine; Linux production)\n", fsmQuarantined, fsSvc)
		if err := quarantineCell(fsSvc); err != nil {
			fmt.Fprintf(os.Stderr, "amberctl: quarantine stub: %v\n", err)
		}
		if err := cooldown.CheckRebuild(fsSvc); err != nil {
			return exitErr(5, "execute-decision: quarantined; rebuild blocked: %v", err)
		}
		return withLifecycleLock(fsSvc, "execute-decision", func() error {
			if err := rebuildCell(fsSvc); err != nil {
				return err
			}
			_ = cooldown.RecordRebuild(fsSvc)
			_ = unquarantineCell(fsSvc)
			return nil
		})
	default:
		return exitErr(3, "execute-decision: unknown decision %q", d)
	}
}

func runDecisionCriticFile(decisionPath string) error {
	if strings.TrimSpace(decisionPath) == "" {
		return nil
	}
	root, err := paths.FindComposeRoot()
	if err != nil {
		return err
	}
	script := filepath.Join(root, "manager", "critic.py")
	cmd := exec.Command("python3", script, decisionPath)
	cmd.Env = os.Environ()
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		if exit, ok := err.(*exec.ExitError); ok {
			return exitErr(exit.ExitCode(), "execute-decision: critic rejected decision")
		}
		return err
	}
	return nil
}

func quarantineCell(svc string) error {
	ip := compose.CellIP(svc)
	if ip == "" {
		return fmt.Errorf("quarantine: unknown cell IP for %q", svc)
	}
	return nftables.QuarantineAdd(ip)
}

func unquarantineCell(svc string) error {
	ip := compose.CellIP(svc)
	if ip == "" {
		return fmt.Errorf("unquarantine: unknown cell IP for %q", svc)
	}
	return nftables.QuarantineDelete(ip)
}
