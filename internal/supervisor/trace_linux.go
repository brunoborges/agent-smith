//go:build linux && (amd64 || arm64)

package supervisor

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/brunoborges/agent-smith/internal/policy"
	"golang.org/x/sys/unix"
)

const ptraceOptions = unix.PTRACE_O_TRACEFORK | unix.PTRACE_O_TRACEVFORK |
	unix.PTRACE_O_TRACECLONE | unix.PTRACE_O_TRACEEXEC | unix.PTRACE_O_EXITKILL

func wait(pid int) (int, unix.WaitStatus, error) {
	for {
		var st unix.WaitStatus
		tid, err := unix.Wait4(pid, &st, unix.WALL|unix.WNOTHREAD, nil)
		if err != unix.EINTR {
			return tid, st, err
		}
	}
}

func trace(root int, uid uint32, rules []policy.Rule, emit policy.Emit) (code int, err error) {
	// Setsid created a new session/PGID. The inherited filter prevents leaving
	// it. Group-scoped waits never consume another exec.Cmd's child statuses.
	pgid := -root
	_, initial, err := wait(root)
	if err != nil {
		return 1, fmt.Errorf("wait for bootstrap: %w", err)
	}
	if !initial.Stopped() {
		return 1, errors.New("bootstrap exited before ptrace startup")
	}
	// On integrity/sink errors kill and reap the private tree. Re-signal
	// stops during cleanup to cover forks already in flight.
	drained := false
	defer func() {
		if !drained {
			if e := terminate(pgid); e != nil {
				code, err = 1, errors.Join(err, e)
			}
		}
	}()
	if initial.StopSignal() != unix.SIGTRAP {
		return 1, errors.New("unexpected bootstrap stop")
	}
	if err := unix.PtraceSetOptions(root, ptraceOptions); err != nil {
		return 1, fmt.Errorf("set required ptrace options: %w", err)
	}
	if err := unix.PtraceCont(root, 0); err != nil {
		return 1, fmt.Errorf("start bootstrap: %w", err)
	}
	rootCode := -1
	for {
		tid, st, err := wait(pgid)
		if err == unix.ECHILD {
			drained = true // PGID is no longer ours to signal
			if rootCode < 0 {
				return 1, errors.New("lost workload exit status")
			}
			return rootCode, nil
		}
		if err != nil {
			return 1, fmt.Errorf("wait for trace event: %w", err)
		}
		if st.Exited() || st.Signaled() {
			if tid == root {
				rootCode = st.ExitStatus()
				if st.Signaled() {
					rootCode = 128 + int(st.Signal())
				}
			}
			continue // keep supervising even if descendants outlive the root
		}
		if !st.Stopped() {
			return 1, errors.New("unexpected wait status")
		}
		sig := st.StopSignal()
		switch st.TrapCause() {
		case unix.PTRACE_EVENT_EXEC:
			// execve and execveat both arrive here after the kernel committed
			// the new image/argv but before it runs its first instruction.
			o, err := observeExec(tid, uid)
			if err != nil {
				return 1, fmt.Errorf("inspect exec: %w", err)
			}
			if r := policy.Match(rules, o); r != nil {
				outcome := "flagged"
				if r.Action == "kill" {
					// exec has committed and de-threaded: tid is the
					// stopped process leader, not a sampled/reused PID.
					// Signal injection via PTRACE_CONT is unreliable at
					// event stops; a real SIGKILL never resumes userspace.
					if err := unix.Kill(tid, unix.SIGKILL); err != nil {
						return 1, fmt.Errorf("kill denied launch: %w", err)
					}
					outcome = "blocked"
				}
				e := policy.Event{Time: time.Now().UTC(), Source: "run", PID: tid, UID: uid,
					Rule: r.ID, Kind: r.Kind, Action: r.Action, Outcome: outcome}
				if err := emit(e); err != nil {
					return 1, fmt.Errorf("record policy decision: %w", err)
				}
				if r.Action == "kill" {
					continue // reap its exit; keep supervising the rest
				}
			}
			sig = 0
		case unix.PTRACE_EVENT_CLONE, unix.PTRACE_EVENT_FORK, unix.PTRACE_EVENT_VFORK:
			// Child already inherits the full option mask and starts stopped.
			sig = 0
		default:
			// Autotraced children start with a synthetic SIGSTOP. Job control
			// isn't supported in this non-interactive, private session.
			switch sig {
			case unix.SIGSTOP, unix.SIGTTIN, unix.SIGTTOU, unix.SIGTSTP:
				sig = 0
			}
		}
		// exec by a non-leader can retire other threads with a stop pending.
		if err := unix.PtraceCont(tid, int(sig)); err != nil && err != unix.ESRCH {
			return 1, fmt.Errorf("continue tracee: %w", err)
		}
	}
}

func terminate(pgid int) error {
	for {
		if err := unix.Kill(pgid, unix.SIGKILL); err != nil && err != unix.ESRCH {
			return fmt.Errorf("terminate workload group: %w", err)
		}
		_, st, err := wait(pgid)
		for err == nil && !st.Stopped() {
			_, st, err = wait(pgid)
		}
		if err == unix.ECHILD {
			return nil
		}
		if err != nil {
			return fmt.Errorf("reap workload group: %w", err)
		}
	}
}

func observeExec(tid int, uid uint32) (policy.Observation, error) {
	base := "/proc/" + strconv.Itoa(tid)
	exe, err := os.Readlink(base + "/exe")
	if err != nil {
		return policy.Observation{}, err
	}
	f, err := os.Open(base + "/cmdline")
	if err != nil {
		return policy.Observation{}, err
	}
	defer f.Close()
	const limit = 2 << 20
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || len(b) == 0 || len(b) > limit || b[len(b)-1] != 0 || bytes.Count(b, []byte{0}) > 16384 {
		return policy.Observation{}, errors.New("cannot inspect complete bounded argument vector")
	}
	return policy.Observation{Kind: "exec", UID: uid, Exe: exe, Argv: strings.Split(string(b[:len(b)-1]), "\x00")}, nil
}
