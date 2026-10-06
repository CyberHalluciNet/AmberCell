// SPDX-License-Identifier: LicenseRef-AmberCell-PSL-1.0

package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/CyberHalluciNet/AmberCell/amberctl/internal/compose"
	"github.com/CyberHalluciNet/AmberCell/amberctl/internal/paths"
	"github.com/CyberHalluciNet/AmberCell/amberctl/internal/review"
)

func runAI(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: amberctl ai decisions|approve|review")
	}
	switch args[0] {
	case "decisions":
		return runAIDecisions(args[1:])
	case "approve":
		return runAIApprove(args[1:])
	case "review":
		return runAIReview(args[1:])
	default:
		return fmt.Errorf("ai: unknown subcommand %q", args[0])
	}
}

func runAIDecisions(args []string) error {
	svc := ""
	for i := 0; i < len(args); i++ {
		if args[i] == "--svc" && i+1 < len(args) {
			svc = args[i+1]
			i++
			continue
		}
		if !strings.HasPrefix(args[i], "-") && svc == "" {
			svc = args[i]
		}
	}
	root := filepath.Join(paths.EvidenceRoot(), "decisions")
	if _, err := os.Stat(root); os.IsNotExist(err) {
		fmt.Println("no decisions recorded")
		return nil
	}
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil || d.IsDir() || filepath.Ext(d.Name()) != ".json" {
			return walkErr
		}
		if svc != "" && !strings.Contains(path, string(os.PathSeparator)+svc+string(os.PathSeparator)) &&
			!strings.Contains(d.Name(), svc) {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var obj map[string]any
		if json.Unmarshal(raw, &obj) != nil {
			return nil
		}
		id, _ := obj["decision_id"].(string)
		dt, _ := obj["decision_type"].(string)
		conf, _ := obj["confidence"].(string)
		fmt.Printf("%s\t%s\tconf=%s\t%s\n", id, dt, conf, path)
		return nil
	})
	return err
}

func runAIApprove(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: amberctl ai approve <decision_id> [--note TEXT]")
	}
	decisionID := args[0]
	note := ""
	for i := 1; i < len(args); i++ {
		if args[i] == "--note" && i+1 < len(args) {
			note = args[i+1]
			i++
		}
	}
	compose.LogInvokerUID("ai approve " + decisionID)
	if err := review.Resolve(decisionID, "approved", note, os.Getuid()); err != nil {
		return err
	}
	fmt.Printf("approved decision %s (preference logged)\n", decisionID)
	return nil
}

func runAIReview(args []string) error {
	svc := ""
	for i := 0; i < len(args); i++ {
		if args[i] == "--svc" && i+1 < len(args) {
			svc = args[i+1]
		}
	}
	items, err := review.ListPending(svc)
	if err != nil {
		return err
	}
	if len(items) == 0 {
		fmt.Println("review queue empty")
		return nil
	}
	for _, it := range items {
		fmt.Printf("%s\t%s\tconf=%s\t%s\n", it.ItemID, it.Svc, it.Confidence, it.Reason)
	}
	return nil
}
