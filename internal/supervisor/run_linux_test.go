//go:build linux && (amd64 || arm64)

package supervisor

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/brunoborges/agent-smith/internal/policy"
	"golang.org/x/sys/unix"
)

func init() {
	BootstrapIfRequested()
	if len(os.Args) < 2 {
		return
	}
	switch os.Args[1] {
	case "__probe":
		if err := checkWorkload(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	case "__thread_exec":
		// Exercise exec from a non-leader: the kernel changes its TID to
		// the group leader's TID while reporting PTRACE_EVENT_EXEC.
		runtime.LockOSThread()
		go func() {
			runtime.LockOSThread()
			if unix.Gettid() == os.Getpid() {
				os.Exit(2)
			}
			_ = unix.Exec(os.Args[2], os.Args[2:], os.Environ())
			os.Exit(3)
		}()
		select {}
	case "__tracer_test_child":
		if os.Getenv("AGENT_SMITH_ISOLATED_TEST") != "1" || len(os.Args) != 3 {
			os.Exit(1)
		}
		code, _ := Run("agent-smith-test", []string{"/bin/sh", "-c",
			`sleep 30 & echo "$$ $!" > "$1"; wait`, "sh", os.Args[2]}, noPush, func(policy.Event) error { return nil })
		os.Exit(code)
	}
}

func checkWorkload() error {
	if os.Geteuid() == 0 || os.Getegid() == 0 || os.Getenv("AGENT_SMITH_SECRET_TEST") != "" ||
		os.Getenv("PATH") != "/usr/local/bin:/usr/bin:/bin" {
		return errors.New("unexpected identity or environment")
	}
	groups, err := os.Getgroups()
	if err != nil || len(groups) != 0 {
		return errors.New("supplementary groups present")
	}
	if account, err := user.Current(); err != nil || os.Getenv("HOME") != account.HomeDir {
		return errors.New("HOME does not match dedicated account")
	}
	st, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return err
	}
	for _, field := range []string{"CapPrm", "CapEff", "CapInh", "CapAmb"} {
		if !strings.Contains(string(st), field+":\t0000000000000000\n") {
			return fmt.Errorf("%s not cleared", field)
		}
	}
	if !strings.Contains(string(st), "NoNewPrivs:\t1\n") {
		return errors.New("no_new_privs not set")
	}
	fd, err := strconv.Atoi(os.Args[2])
	if err != nil {
		return err
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err != unix.EBADF {
		return errors.New("descriptor inherited from supervisor")
	}
	// CLONE_THREAD without CLONE_SIGHAND is deliberately invalid, so even
	// a broken filter cannot create a child during this check.
	if _, _, e := unix.RawSyscall6(unix.SYS_CLONE, unix.CLONE_THREAD|unix.CLONE_UNTRACED, 0, 0, 0, 0, 0); e != unix.EPERM {
		return fmt.Errorf("CLONE_UNTRACED not filtered: %v", e)
	}
	if _, _, e := unix.Syscall(unix.SYS_CLONE3, 0, 0, 0); e != unix.ENOSYS {
		return fmt.Errorf("unexpected clone3 result: %v", e)
	}
	if e := unix.Setpgid(0, 0); e != unix.EPERM {
		return fmt.Errorf("unexpected setpgid result: %v", e)
	}
	if _, _, e := unix.Syscall(unix.SYS_SETUID, uintptr(os.Getuid()), 0, 0); e != unix.EPERM {
		return fmt.Errorf("unexpected setuid result: %v", e)
	}
	return nil
}

// Run only in an opt-in, disposable, isolated Linux container/VM with git,
// an agent-smith-test account with its own home, ptrace permission and no host credentials. No network or
// persistent host mounts are needed. Do not enable on a live host.
func isolated(t *testing.T) *syscall.Credential {
	t.Helper()
	if os.Getenv("AGENT_SMITH_ISOLATED_TEST") != "1" {
		t.Skip("requires AGENT_SMITH_ISOLATED_TEST=1 in a disposable Linux system")
	}
	if os.Geteuid() != 0 {
		t.Fatal("isolated test requires root")
	}
	u, err := user.Lookup("agent-smith-test")
	if err != nil {
		t.Fatal(err)
	}
	uid, err := nonRootID(u.Uid)
	if err != nil {
		t.Fatal(err)
	}
	gid, err := nonRootID(u.Gid)
	if err != nil {
		t.Fatal(err)
	}
	return &syscall.Credential{Uid: uid, Gid: gid}
}

var noPush = []policy.Rule{{ID: "no-push", Kind: "git-push", Action: "kill"}}

func TestIsolatedBootstrap(t *testing.T) {
	isolated(t)
	t.Setenv("AGENT_SMITH_SECRET_TEST", "must-not-leak")
	fd, err := unix.FcntlInt(0, unix.F_DUPFD, 200) // deliberately not CLOEXEC
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	code, err := Run("agent-smith-test", []string{"/proc/self/exe", "__probe", strconv.Itoa(fd)}, noPush, func(policy.Event) error { return nil })
	if code != 0 || err != nil {
		t.Fatalf("probe: code=%d err=%v", code, err)
	}
	if _, err := Run("root", []string{"/bin/true"}, noPush, func(policy.Event) error { return nil }); err == nil {
		t.Fatal("accepted root workload")
	}
}

func fixtureDir(t *testing.T, cred *syscall.Credential) string {
	t.Helper()
	// A direct child of /run: default go test build/temp ancestors may be
	// mode 0700 and intentionally inaccessible to the restricted identity.
	dir, err := os.MkdirTemp("/run", "agent-smith-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	if err := os.Chown(dir, int(cred.Uid), int(cred.Gid)); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestIsolatedPreventGitPush(t *testing.T) {
	cred := isolated(t)
	dir := fixtureDir(t, cred)
	repo, bare := filepath.Join(dir, "repo"), filepath.Join(dir, "bare")
	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command("/usr/bin/git", args...)
		cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + dir, "GIT_CONFIG_NOSYSTEM=1"}
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: cred}
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("fixture git: %v: %s", err, out)
		}
	}
	git("init", "--bare", bare)
	git("init", repo)
	git("-C", repo, "-c", "user.name=test", "-c", "user.email=test@example.invalid", "commit", "--allow-empty", "-m", "test")
	// Positive control: identical binary, identity, repo and local transport
	// can update this remote without a gate. No external destination involved.
	git("-C", repo, "push", bare, "HEAD:refs/heads/control")
	git("--git-dir", bare, "show-ref", "--verify", "refs/heads/control")
	var seen []policy.Event
	emit := func(e policy.Event) error { seen = append(seen, e); return nil }
	if code, err := Run("agent-smith-test", []string{"/usr/bin/git", "ls-remote", bare}, noPush, emit); code != 0 || err != nil || len(seen) != 0 {
		t.Fatalf("read blocked: code=%d err=%v events=%v", code, err, seen)
	}
	flag := []policy.Rule{{ID: "read", Kind: "exec", Path: "/usr/bin/git", ArgsPrefix: []string{"ls-remote"}, Action: "flag"}}
	if code, err := Run("agent-smith-test", []string{"/usr/bin/git", "ls-remote", bare}, flag, emit); code != 0 || err != nil || len(seen) != 1 || seen[0].Outcome != "flagged" {
		t.Fatalf("flagged read: code=%d err=%v events=%v", code, err, seen)
	}
	const branch = "HEAD:refs/heads/blocked"
	push := []string{"/usr/bin/git", "-C", repo, "push", bare, branch}
	for _, argv := range [][]string{
		push,
		append([]string{"/proc/self/exe", "__thread_exec"}, push...),
	} {
		seen = nil
		code, err := Run("agent-smith-test", argv, noPush, emit)
		if code != 137 || err != nil || len(seen) != 1 || seen[0].Rule != "no-push" || seen[0].Outcome != "blocked" {
			t.Fatalf("denial: code=%d err=%v events=%v", code, err, seen)
		}
		if _, err := os.Stat(filepath.Join(bare, "refs/heads/blocked")); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("denied ref exists or cannot verify")
		}
	}

	// Parent and sibling survive. A second push is still supervised.
	seen = nil
	shell := append([]string{"/bin/sh", "-c", `
		sleep 0.05 & sibling=$!
		"$@"; test "$?" = 137 || exit 1
		"$@"; test "$?" = 137 || exit 2
		wait "$sibling"`, "sh"}, push...)
	if code, err := Run("agent-smith-test", shell, noPush, emit); code != 0 || err != nil || len(seen) != 2 {
		t.Fatalf("supervision after denial: code=%d err=%v events=%v", code, err, seen)
	}
	// An event sink failure, unlike an ordinary policy decision, tears down
	// the whole group rather than silently permitting unaudited operations.
	pidfile := filepath.Join(dir, "background.pid")
	shell = append([]string{"/bin/sh", "-c", `sleep 60 & echo $! > "$1"; shift; "$@"; wait`, "sh", pidfile}, push...)
	sinkErr := errors.New("unavailable event sink")
	if _, err := Run("agent-smith-test", shell, noPush, func(policy.Event) error { return sinkErr }); !errors.Is(err, sinkErr) {
		t.Fatalf("sink failure not propagated: %v", err)
	}
	if _, err := os.Stat(filepath.Join(bare, "refs/heads/blocked")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("denied descendant changed ref or cannot verify")
	}
	b, err := os.ReadFile(pidfile)
	if err != nil {
		t.Fatal(err)
	}
	sleeper, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		t.Fatal(err)
	}
	// An orphaned grandchild may still be waiting for container init to reap
	// its zombie. The supervisor is not its real parent; it must not be live.
	status, err := os.ReadFile("/proc/" + strconv.Itoa(sleeper) + "/status")
	if !errors.Is(err, os.ErrNotExist) && (err != nil || !strings.Contains(string(status), "State:\tZ")) {
		t.Fatal("background process survived tree termination")
	}
}

func TestIsolatedTracerDeath(t *testing.T) {
	dir := fixtureDir(t, isolated(t))
	file := filepath.Join(dir, "ready")
	cmd := exec.Command("/proc/self/exe", "__tracer_test_child", file)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()
	var pids []string
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if b, _ := os.ReadFile(file); len(strings.Fields(string(b))) == 2 {
			pids = strings.Fields(string(b))
			break
		}
	}
	if len(pids) != 2 {
		t.Fatal("workload did not become ready")
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	for _, pid := range pids {
		gone := false
		for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
			b, err := os.ReadFile("/proc/" + pid + "/status")
			if errors.Is(err, os.ErrNotExist) || strings.Contains(string(b), "State:\tZ") {
				gone = true
				break
			}
		}
		if !gone {
			t.Errorf("tracee %s survived tracer death", pid)
		}
	}
}
