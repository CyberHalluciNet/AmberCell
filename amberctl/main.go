// SPDX-License-Identifier: LicenseRef-AmberCell-PSL-1.0
// amberctl — AmberCell operator CLI (Stage-1 FTP).

package main

import (
	"fmt"
	"os"

	"github.com/CyberHalluciNet/AmberCell/amberctl/internal/cli"
)

func main() {
	if err := cli.Run(os.Args[1:]); err != nil {
		if ee, ok := err.(*cli.ExitError); ok {
			fmt.Fprintln(os.Stderr, ee.Message)
			os.Exit(ee.Code)
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
