package watch

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/brunoborges/agent-smith/internal/policy"
)

func TestOrdinaryInputCannotArm(t *testing.T) {
	h := policy.Host{Armed: true, Rules: []policy.Rule{connectRule}}
	var outcomes []string
	err := Run(strings.NewReader(connectFixture()), h, func(e policy.Event) error {
		outcomes = append(outcomes, e.Outcome)
		return nil
	})
	if err != nil || strings.Join(outcomes, ",") != "unverified-source,disarmed" {
		t.Fatalf("%v: %v", outcomes, err)
	}
}

func TestProtectedSessionAndCredentials(t *testing.T) {
	for _, cg := range []string{"/system.slice/web.service", "/user.slice/user-1100.slice/user@1100.service",
		"/user.slice/user-1100.slice/session-2.scope/worker", "/user.slice/user-1101.slice/session-2.scope", "/"} {
		if sessionScope("0::"+cg+"\n", "1100") {
			t.Errorf("allowed %s", cg)
		}
	}
	if !sessionScope("0::/user.slice/user-1100.slice/session-2.scope\n", "1100") {
		t.Fatal("expected login session to pass")
	}
	const status = `Tgid: 8
NSpid: 9
TracerPid: 0
Uid: 1100 1100 1100 1100
Gid: 1100 1100 1100 1100
CapInh: 0000000000000000
CapPrm: 0000000000000000
CapEff: 0000000000000000
CapAmb: 0000000000000000
`
	if !safeStatus(status, "1100", 8, 9) {
		t.Fatal("expected unprivileged thread to pass")
	}
	for _, s := range []string{strings.Replace(status, "TracerPid: 0", "TracerPid: 1", 1),
		strings.Replace(status, "1100 1100 1100 1100", "1100 0 1100 1100", 1),
		strings.Replace(status, "0000000000000000", "0000000000000001", 1),
		strings.Replace(status, "NSpid: 9", "NSpid: 9 1", 1)} {
		if safeStatus(s, "1100", 8, 9) {
			t.Fatal("allowed a protected task")
		}
	}
	if outsideAncestry(os.Getpid()) || outsideAncestry(1) ||
		!infra("/bin/systemd-logind", nil) || !infra("/opt/company/worker", []string{"/opt/company/worker"}) {
		t.Fatal("failed infrastructure protections")
	}
}

func TestProcStartIsConservative(t *testing.T) {
	st, ok := task(os.Getpid())
	if !ok {
		t.Fatal("could not read own start tick")
	}
	before, ok := latestStart(st.start, clockTicks())
	if !ok || time.Since(before) > time.Minute || time.Until(before) > time.Second {
		t.Fatalf("implausible derived process start: %v", before)
	}
	e := evidence{when: before.Add(-time.Millisecond), ppid: st.parent}
	if matchesStart(st, clockTicks(), e) {
		t.Fatal("a possibly reused PID must not qualify")
	}
	e.when = before.Add(time.Second)
	if !matchesStart(st, clockTicks(), e) {
		t.Fatal("earlier unchanged process should qualify")
	}
	e.ppid++
	if matchesStart(st, clockTicks(), e) {
		t.Fatal("parent identity mismatch must not qualify")
	}
}
