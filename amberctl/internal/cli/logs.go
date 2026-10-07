// SPDX-License-Identifier: LicenseRef-AmberCell-PSL-1.0

package cli

import (
	"fmt"
	"os"

	"github.com/CyberHalluciNet/AmberCell/amberctl/internal/compose"
)

func runLogs(args []string) error {
	if len(args) > 1 {
		return fmt.Errorf("usage: amberctl logs [svc]")
	}
	svc := ""
	if len(args) == 1 {
		if !supportedCell(args[0]) {
			return fmt.Errorf("logs: unknown svc %q", args[0])
		}
		svc = args[0]
	}
	return compose.Logs(svc, os.Stdout, os.Stderr)
}
