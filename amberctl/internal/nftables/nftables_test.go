// SPDX-License-Identifier: LicenseRef-AmberCell-PSL-1.0

package nftables

import (
	"runtime"
	"testing"
)

func TestQuarantineRejectsEmptyIP(t *testing.T) {
	if err := QuarantineAdd(""); err == nil {
		t.Fatal("expected error for empty IP")
	}
}

func TestQuarantineStubNonLinux(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("stub path is for non-Linux")
	}
	t.Setenv("AMBER_FORCE_NFT", "")
	if err := QuarantineAdd("172.30.30.10"); err != nil {
		t.Fatal(err)
	}
	if err := QuarantineDelete("172.30.30.10"); err != nil {
		t.Fatal(err)
	}
}
