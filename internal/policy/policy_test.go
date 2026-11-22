package policy

import (
	"net/netip"
	"os"
	"strings"
	"testing"
)

func TestReviewProfile(t *testing.T) {
	f, err := os.Open("../../examples/policy.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	c, err := decode(f)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		exe  string
		argv []string
		want bool
	}{
		{"/usr/bin/git", []string{"git", "push"}, true},
		{"/usr/bin/git", []string{"something-else", "-C", "repo", "-c", "foo.bar=x", "--git-dir=.git", "push", "origin"}, true},
		{"/usr/bin/git", []string{"git", "-C", "push", "diff", "--", "push"}, false},
		{"/usr/bin/git", []string{"git", "--help", "push"}, false},
		{"/usr/bin/git", []string{"git-push", "origin"}, true},
		{"/bin/echo", []string{"git", "push"}, false},
		{"/bin/sh", []string{"sh", "-c", "git push"}, false},
	} {
		r := Match(c.Profiles["review"], Observation{Kind: "exec", Exe: tc.exe, Argv: tc.argv})
		if (r != nil && r.Action == "kill") != tc.want {
			t.Errorf("%s %q: got %v, want kill=%t", tc.exe, tc.argv, r, tc.want)
		}
	}
	dest := Observation{Kind: "connect", UID: 1100, Exe: "/tmp/custom-client", Destination: netip.MustParseAddrPort("192.0.2.10:443")}
	if r := Match(c.Host.Rules, dest); r == nil || r.Action != "flag" || c.Host.Armed {
		t.Fatal("sample must flag restricted connections without arming host kills")
	}
	dest.UID++
	if Match(c.Host.Rules, dest) != nil {
		t.Fatal("review policy affected another account")
	}
}

func TestMatchPrecedenceAndPath(t *testing.T) {
	rules := []Rule{
		{ID: "warn", Kind: "exec-dir", Path: "/opt/review", Action: "flag"},
		{ID: "stop", Kind: "exec", Path: "/opt/review/tool", ArgsPrefix: []string{"publish"}, Action: "kill"},
	}
	obs := Observation{Kind: "exec", Exe: "/opt/reviewer/tool"}
	if Match(rules, obs) != nil {
		t.Fatal("directory prefix matched different directory")
	}
	obs.Exe = "/opt/review/tool"
	if r := Match(rules, obs); r == nil || r.ID != "warn" {
		t.Fatal("unmatched argv should flag")
	}
	obs.Argv = []string{"tool", "publish", "remote"}
	if r := Match(rules, obs); r == nil || r.ID != "stop" {
		t.Fatal("kill must take precedence")
	}
}

func TestRejectInvalidPolicy(t *testing.T) {
	for _, s := range []string{
		`{}`, `{"host":{"arme":true}}`, `null`, `{} {}`,
		`{"profiles":{"review":[]}}`,
		`{"host":{"rules":[{"id":"a","action":"kill","kind":"exec-dir","path":"/tmp/../"}]}}`,
		`{"host":{"rules":[{"id":"a","action":"kill","kind":"connect","destination":"example.com:443"}]}}`,
		`{"profiles":{"p":[{"id":"a","action":"kill","kind":"connect","destination":"127.0.0.1:443"}]}}`,
		`{"profiles":{"p":[{"id":"a","action":"kill","kind":"git-push"},{"id":"a","action":"flag","kind":"git-push"}]}}`,
	} {
		if _, err := decode(strings.NewReader(s)); err == nil {
			t.Errorf("accepted invalid policy: %s", s)
		}
	}
}
