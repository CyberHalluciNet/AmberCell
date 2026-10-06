// SPDX-License-Identifier: LicenseRef-AmberCell-PSL-1.0

package cli

import (
	"strings"
	"testing"
)

func TestParseInitArgsCellsImpliesWizard(t *testing.T) {
	yes, force, cells, err := parseInitArgs([]string{"--cells", "ftp,smtp"})
	if err != nil {
		t.Fatal(err)
	}
	if yes || !force || len(cells) != 2 {
		t.Fatalf("yes=%v force=%v cells=%v", yes, force, cells)
	}
}

func TestParseInitArgsYesCellsConflict(t *testing.T) {
	yes, force, _, err := parseInitArgs([]string{"--yes", "--cells", "ftp"})
	if err != nil {
		t.Fatal(err)
	}
	if !yes || !force {
		t.Fatalf("expected yes+forceWizard so runInit rejects the combo (yes=%v force=%v)", yes, force)
	}
	err = runInit([]string{"--yes", "--cells", "ftp"})
	if err == nil || !strings.Contains(err.Error(), "conflicts") {
		t.Fatalf("expected conflict error, got %v", err)
	}
}
