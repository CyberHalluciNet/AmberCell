// SPDX-License-Identifier: LicenseRef-AmberCell-PSL-1.0

package conntrack

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
)

// FlushCell drops conntrack entries for the cell address before recreate (Linux).
// On non-Linux hosts (e.g. Darwin lab builds) logs the would-run command only.
func FlushCell(cellIP string) error {
	if cellIP == "" {
		cellIP = "172.30.30.10"
	}
	if runtime.GOOS != "linux" {
		fmt.Fprintf(
			os.Stderr,
			"amberctl: conntrack flush stub (GOOS=%s): would run conntrack -D -s %s and conntrack -D -d %s\n",
			runtime.GOOS, cellIP, cellIP,
		)
		return nil
	}
	for _, args := range [][]string{
		{"-D", "-s", cellIP},
		{"-D", "-d", cellIP},
	} {
		cmd := exec.Command("conntrack", args...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			// conntrack may be absent in lab kernels; log and continue (Stage-1 stub).
			fmt.Fprintf(os.Stderr, "amberctl: conntrack %v: %v (continuing)\n", args, err)
		}
	}
	return nil
}
