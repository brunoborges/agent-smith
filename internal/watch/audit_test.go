package watch

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/brunoborges/agent-smith/internal/policy"
)

const (
	timestamp = "1700000000.100"
	execSys   = `arch=c000003e syscall=59 success=yes items=1 ppid=51 pid=60 auid=1100 uid=1100 euid=1100 suid=1100 fsuid=1100 comm="fixture tool" exe="/opt/tools/private-tool" key="agent_smith_exec"`
	connSys   = `arch=c00000b7 syscall=203 success=no exit=-115 items=0 ppid=51 pid=67 auid=1100 uid=1100 euid=1100 suid=1100 fsuid=1100 exe="/usr/bin/python3" key="agent_smith_connect"`
	args      = `argc=3 a0="tool" a1=73656E64 a2="private argument with spaces"`
	pathRec   = `item=0 name="/opt/tools/private-tool" inode=1234 dev=08:01 nametype=NORMAL`
	sock      = `saddr=020001BBC00002010000000000000000`
)

func rec(id int, typ, body string) string {
	return fmt.Sprintf("type=%s msg=audit(%s:%d): %s\n", typ, timestamp, id, body)
}

func connectFixture() string {
	return rec(1, "SYSCALL", connSys) + rec(1, "SOCKADDR", sock) + rec(1, "EOE", "")
}

var connectRule = policy.Rule{ID: "endpoint", Kind: "connect", Action: "kill", Destination: "192.0.2.1:443"}

func replay(t *testing.T, stream string, host policy.Host, response responder) []policy.Event {
	t.Helper()
	first := true
	now := func() time.Time {
		if first {
			first = false
			return time.Unix(1700000000, 0)
		}
		return time.Unix(1700000000, 200_000_000)
	}
	var out []policy.Event
	if err := consume(strings.NewReader(stream), host, func(e policy.Event) error {
		out = append(out, e)
		return nil
	}, response, now); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestCorrelateInterleavedRawAndRedact(t *testing.T) {
	h := policy.Host{Rules: []policy.Rule{
		{ID: "verb", Kind: "exec", Action: "flag", Path: "/opt/tools/private-tool", ArgsPrefix: []string{"send"}},
		connectRule,
	}}
	stream := rec(1, "SYSCALL", execSys) + rec(2, "SYSCALL", connSys) +
		rec(1, "EXECVE", args) + rec(2, "SOCKADDR", sock) + rec(2, "EOE", "") +
		rec(1, "PATH", pathRec) + rec(1, "EOE", "")
	events := replay(t, stream, h, nil)
	if len(events) != 2 || events[0].PID != 67 || events[0].UID != 1100 || events[0].Rule != "endpoint" ||
		events[0].Action != "flag" || events[0].Outcome != "disarmed" || events[1].Rule != "verb" || events[1].PID != 60 {
		t.Fatalf("unexpected events: %+v", events)
	}
	b, err := json.Marshal(events)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"private", "192.0.2.1", "443", "/opt", "send", "python", "73656E64"} {
		if strings.Contains(string(b), secret) {
			t.Fatalf("sensitive audit metadata escaped: %s", b)
		}
	}
	h.Rules = []policy.Rule{{ID: "dir", Kind: "exec-dir", Action: "flag", Path: "/opt/tools"}}
	if e := replay(t, stream, h, nil); len(e) != 1 || e[0].Rule != "dir" {
		t.Fatalf("directory policy did not receive a complete exec: %+v", e)
	}
}

func TestArmedStreamRejectsAmbiguousInputs(t *testing.T) {
	h := policy.Host{Armed: true, Rules: []policy.Rule{connectRule}}
	invoke := func(e evidence) string {
		t.Fatalf("unexpected responder call for pid %d", e.pid)
		return ""
	}
	for name, stream := range map[string]string{
		"lost":           rec(2, "DAEMON_LOST", "") + connectFixture(),
		"remote":         "node=host " + connectFixture(),
		"enriched":       strings.ReplaceAll(connectFixture(), " key=", "\x1d key="),
		"user text":      rec(1, "USER_CMD", `msg='`+strings.TrimSpace(rec(1, "SYSCALL", connSys))+`'`) + rec(1, "SOCKADDR", sock) + rec(1, "EOE", ""),
		"no terminator":  strings.TrimSuffix(connectFixture(), rec(1, "EOE", "")),
		"partial line":   strings.TrimSuffix(connectFixture(), "\n"),
		"serial mix":     strings.Replace(connectFixture(), rec(1, "SOCKADDR", sock), rec(2, "SOCKADDR", sock), 1),
		"duplicate":      strings.Replace(connectFixture(), rec(1, "SOCKADDR", sock), strings.Repeat(rec(1, "SOCKADDR", sock), 2), 1),
		"wrong syscall":  strings.ReplaceAll(connectFixture(), "syscall=203", "syscall=99"),
		"wrong key":      strings.ReplaceAll(connectFixture(), connKey, "different"),
		"bad numeric":    strings.ReplaceAll(connectFixture(), "pid=67", "pid=+0"),
		"missing EUID":   strings.ReplaceAll(connectFixture(), "euid=1100 ", ""),
		"missing record": strings.ReplaceAll(connectFixture(), "items=0", "items=1"),
		"future":         strings.ReplaceAll(connectFixture(), timestamp, "1700000001.000"),
		"pre-start":      strings.ReplaceAll(connectFixture(), timestamp, "1699999999.999"),
	} {
		t.Run(name, func(t *testing.T) {
			for _, e := range replay(t, stream, h, invoke) {
				if e.Action == "kill" {
					t.Fatal(e)
				}
			}
		})
	}
}

func TestArmedOnlyAfterCompleteScopedRecords(t *testing.T) {
	h := policy.Host{Armed: true, Rules: []policy.Rule{connectRule}}
	// Auditd starts plugins before DAEMON_START. Other rules don't need EOE
	// to be ignored, including enough events to exceed the correlation cap.
	var b strings.Builder
	b.WriteString(rec(1, "DAEMON_START", ""))
	for i := 0; i <= maxPending; i++ {
		b.WriteString(rec(i, "SYSCALL", strings.ReplaceAll(connSys, connKey, "other")))
	}
	b.WriteString(connectFixture())
	calls := 0
	events := replay(t, b.String(), h, func(e evidence) string {
		calls++
		if e.pid != 67 || !e.credsOK || e.Kind != "connect" {
			t.Fatalf("bad evidence: %+v", e)
		}
		return "guarded"
	})
	if calls != 1 || len(events) != 2 || events[1].Action != "flag" || events[1].Outcome != "guarded" {
		t.Fatalf("incorrect guarded disposition: %+v", events)
	}
}

func TestBoundsAndIncompleteAreReported(t *testing.T) {
	h := policy.Host{Armed: true, Rules: []policy.Rule{connectRule}}
	var b strings.Builder
	for i := 10; i <= maxPending+10; i++ {
		b.WriteString(rec(i, "SYSCALL", connSys))
	}
	events := replay(t, b.String()+connectFixture(), h, func(e evidence) string {
		t.Fatal("loss must disarm")
		return ""
	})
	if len(events) < 2 || events[0].Outcome != "correlation-overflow" || events[1].Outcome != "disarmed" {
		t.Fatal(events)
	}
	b.Reset()
	if err := consume(strings.NewReader(strings.Repeat("x", maxLine+1)), h, func(e policy.Event) error {
		b.WriteString(e.Outcome)
		return nil
	}, nil, time.Now); err == nil || !strings.Contains(b.String(), "incomplete-stream") {
		t.Fatalf("overlong input not rejected: %v, %s", err, b.String())
	}
}

func TestIncompleteExecDoesNotMatchPrefix(t *testing.T) {
	h := policy.Host{Rules: []policy.Rule{{ID: "verb", Action: "kill", Kind: "exec", Path: "/opt/tools/private-tool", ArgsPrefix: []string{"send"}}}}
	for _, body := range []string{`argc=3 a0="tool" a1="send"`, `argc=3 a0="tool" a1="send" a2_len=100000`,
		`argc=3 a0="tool" a1="send" a1="other"`, `argc=3 a0="tool" a1="send" a2=zz`} {
		stream := rec(1, "SYSCALL", execSys) + rec(1, "PATH", pathRec) + rec(1, "EXECVE", body) + rec(1, "EOE", "")
		out := replay(t, stream, h, nil)
		if len(out) != 1 || out[0].Outcome != "incomplete-event" || out[0].Rule != "" {
			t.Fatal(out)
		}
	}
}

func TestSinkFailurePreventsResponse(t *testing.T) {
	h := policy.Host{Armed: true, Rules: []policy.Rule{connectRule}}
	want := errors.New("sink unavailable")
	err := consume(strings.NewReader(connectFixture()), h, func(e policy.Event) error { return want }, func(e evidence) string {
		t.Fatal("must not signal without a working event sink")
		return ""
	}, func() time.Time { return time.UnixMilli(1700000000100) })
	if !errors.Is(err, want) {
		t.Fatal(err)
	}
}

func TestIPv6NetworkOrder(t *testing.T) {
	v, ok := destination("0A0023280000000020010DB800000000000000000000000100000000")
	if !ok || v.String() != "[2001:db8::1]:9000" {
		t.Fatalf("bad IPv6 decode: %v", v)
	}
}
