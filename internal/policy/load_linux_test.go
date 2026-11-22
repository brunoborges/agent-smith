package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadRefusesUntrustedComponents(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("tests root-owned policy paths")
	}
	dir, err := os.MkdirTemp("/root", "smith-policy-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	p := filepath.Join(dir, "policy.json")
	b, err := os.ReadFile("../../examples/policy.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, b, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "symlink")
	if err := os.Symlink(p, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(link); err == nil {
		t.Fatal("accepted a symlink")
	}
	if err := os.Chmod(dir, 0777); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err == nil {
		t.Fatal("accepted a writable directory in policy path")
	}
}
