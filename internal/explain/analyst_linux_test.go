package explain

import (
	"io"
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestLinuxCredentials(t *testing.T) {
	const clean = "Uid: 999 999 999 999\nGid: 998 998 998 998\nGroups: 998\nCapInh: 0\nCapPrm: 0\nCapEff: 0\nCapAmb: 0\n"
	if !ordinaryIdentity(clean, "999", "998") {
		t.Fatal("ordinary dedicated identity rejected")
	}

	for _, bad := range [][2]string{
		{"999 999 999 999", "999 999 0 999"}, {"998 998 998 998", "998 998 0 998"},
		{"Groups: 998", "Groups: 998 27"}, {"CapPrm: 0", "CapPrm: a"},
		{"CapAmb: 0", "CapAmb: 1"}, {"CapEff: 0", "CapEff: 4"}, {"CapInh: 0", ""},
	} {
		if ordinaryIdentity(strings.Replace(clean, bad[0], bad[1], 1), "999", "998") {
			t.Fatalf("accepted identity with %q", bad[1])
		}
	}
	// Must fail before reading input or looking up credentials.
	if os.Getuid() == 0 && Run("codex", nil, io.Discard) == nil {
		t.Fatal("root was accepted")
	}
}

func TestRejectAmbientDescriptor(t *testing.T) {
	fd, err := unix.Open("/dev/null", unix.O_RDONLY, 0) // deliberately not close-on-exec
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if noInheritedFDs() {
		t.Fatal("accepted a descriptor that could survive exec")
	}
}
