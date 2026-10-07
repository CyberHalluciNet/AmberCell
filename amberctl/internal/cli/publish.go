// SPDX-License-Identifier: LicenseRef-AmberCell-PSL-1.0

package cli

import (
	"flag"
	"fmt"
	"os"

	"github.com/CyberHalluciNet/AmberCell/amberctl/internal/compose"
	"github.com/CyberHalluciNet/AmberCell/amberctl/internal/publish"
)

func runPublish(args []string) error {
	fs := flag.NewFlagSet("publish", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	class := fs.String("class", "summary", "summary|full")
	includePcap := fs.Bool("pcap", false, "include closed pcap slices (opt-in, large)")
	svc := fs.String("svc", "", "optional svc filter (e.g. ftp, ssh, dns)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *svc != "" && !supportedCell(*svc) {
		return fmt.Errorf("publish: unknown svc %q", *svc)
	}
	compose.LogInvokerUID("publish")
	opts := publish.Options{
		Class:       publish.Class(*class),
		IncludePcap: *includePcap,
		SvcFilter:   *svc,
	}
	dir, err := publish.Run(opts)
	if err != nil {
		return err
	}
	fmt.Printf("published dead drop bundle: %s\n", dir)
	fmt.Fprintf(os.Stderr, "amberctl: publish class=%s\n", *class)
	return nil
}
