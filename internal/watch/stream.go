package watch

import (
	"bufio"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/brunoborges/agent-smith/internal/policy"
)

const (
	maxAge     = 2 * time.Second
	maxPending = 128
	maxLine    = 16 * 1024
)

// nil responder is strictly report-only. The sole production constructor of
// a responder attests the actual reader and returns a pidfd-only implementation.
type responder func(evidence) string

func consume(r io.Reader, host policy.Host, emit policy.Emit, respond responder, now func() time.Time) error {
	pending := make(map[recordID]*group)
	start := now()
	nextSweep := start.Add(maxAge)
	health := func(outcome string) error {
		return emit(policy.Event{Time: now().UTC(), Source: "watch", Kind: "audit", Action: "flag", Outcome: outcome})
	}
	// A known loss invalidates confidence for the rest of this invocation.
	degrade := func(outcome string) error {
		respond = nil
		return health(outcome)
	}
	if host.Armed && respond == nil {
		if err := health("unverified-source"); err != nil {
			return err
		}
	}
	br := bufio.NewReaderSize(r, maxLine)
	warnedEnriched := false
	for {
		line, err := br.ReadSlice('\n')
		if err != nil {
			if len(pending) != 0 || len(line) != 0 || err != io.EOF {
				if outErr := degrade("incomplete-stream"); outErr != nil {
					return outErr
				}
			}
			if err == io.EOF {
				return nil
			}
			// Reader errors can contain arbitrary data. Don't forward them.
			return errors.New("audit dispatcher read or record size error")
		}
		t := now()
		if !t.Before(nextSweep) {
			expired := false
			for id, g := range pending {
				if t.Sub(g.first) >= maxAge {
					delete(pending, id)
					expired = true
				}
			}
			if expired {
				if err := degrade("incomplete-timeout"); err != nil {
					return err
				}
			}
			nextSweep = t.Add(maxAge / 2)
		}
		s := string(line[:len(line)-1])
		if prefix, _, enriched := strings.Cut(s, "\x1d"); enriched {
			// Enrichment appends interpreted fields, including a second set
			// of identities. Only the raw prefix is usable for reporting.
			s = prefix
			if !warnedEnriched {
				if err := degrade("enriched-report-only"); err != nil {
					return err
				}
				warnedEnriched = true
			}
		}
		typ, id, body, ok := header(s)
		if !ok || strings.IndexByte(s, 0) >= 0 {
			clear(pending)
			if err := degrade("invalid-framing"); err != nil {
				return err
			}
			continue
		}
		switch typ {
		case "DAEMON_LOST", "DAEMON_ABORT", "DAEMON_ERR", "DAEMON_END", "DAEMON_CONFIG":
			clear(pending)
			if err := degrade("dispatcher-discontinuity"); err != nil {
				return err
			}
			continue
		case "SYSCALL", "EXECVE", "SOCKADDR", "PATH":
			g := pending[id]
			if g == nil {
				// The kernel emits SYSCALL first in audit_log_exit. Do not
				// consume slots (or report timeouts) for unrelated policy
				// keys, unrelated PATH records, or an orphaned trailing half.
				if typ != "SYSCALL" {
					continue
				}
				sys, ok := fields(body)
				if !ok {
					if err := health("invalid-syscall"); err != nil {
						return err
					}
					continue
				}
				key, _ := text(sys["key"])
				if key != execKey && key != connKey {
					continue
				}
				if len(pending) >= maxPending {
					clear(pending)
					if err := degrade("correlation-overflow"); err != nil {
						return err
					}
				}
				g = &group{first: t, records: 1, bytes: len(body), sys: sys}
				pending[id] = g
				continue
			}
			g.add(typ, body)
		case "EOE":
			g := pending[id]
			if g == nil {
				continue
			}
			delete(pending, id)
			e, result := g.observe(id)
			if result == "" {
				continue
			}
			if result != "observed" || body != "" {
				if result == "unsupported" {
					// e.g. AF_UNIX, not a lost event.
					continue
				}
				if err := health("incomplete-event"); err != nil {
					return err
				}
				continue
			}
			rule := policy.Match(host.Rules, e.Observation)
			if rule == nil {
				continue
			}
			out := policy.Event{Time: t.UTC(), Source: "watch", PID: e.pid, UID: e.UID,
				Rule: rule.ID, Kind: rule.Kind, Action: "flag", Outcome: "reported"}
			if rule.Action == "kill" {
				switch {
				case !host.Armed || respond == nil:
					out.Outcome = "disarmed"
				case e.when.Before(start) || !fresh(e.when, t) || t.Sub(g.first) >= maxAge:
					out.Outcome = "stale"
				default:
					// If redacted evidence cannot be logged, don't take action.
					out.Outcome = "checking"
					if err := emit(out); err != nil {
						return err
					}
					out.Outcome = respond(e)
					if out.Outcome == "signal-sent" || out.Outcome == "signal-failed" {
						out.Action = "kill"
					}
				}
			}
			if err := emit(out); err != nil {
				return err
			}
		}
	}
}

func fresh(event, now time.Time) bool {
	age := now.Sub(event)
	return age >= 0 && age < maxAge
}
