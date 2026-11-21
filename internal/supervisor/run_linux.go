//go:build linux && (amd64 || arm64)

package supervisor

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"

	"github.com/brunoborges/agent-smith/internal/policy"
	"golang.org/x/sys/unix"
)

const bootstrapArg = "__agent_smith_bootstrap"

// Run launches an absolute executable as a dedicated local identity. The caller
// supplies a validated profile and a trusted event sink. No shell is involved.
func Run(username string, argv []string, rules []policy.Rule, emit policy.Emit) (int, error) {
	if os.Geteuid() != 0 {
		return 1, errors.New("supervised launch requires root")
	}
	if len(argv) == 0 || !filepath.IsAbs(argv[0]) || username == "" || len(rules) == 0 || emit == nil {
		return 1, errors.New("launch requires an identity, absolute executable, rules and event sink")
	}
	for _, r := range rules {
		if (r.Action != "kill" && r.Action != "flag") || (r.Kind != "exec" && r.Kind != "exec-dir" && r.Kind != "git-push") {
			return 1, errors.New("unsupported run rule")
		}
	}
	u, err := user.Lookup(username)
	if err != nil {
		return 1, fmt.Errorf("look up workload identity: %w", err)
	}
	uid, err := nonRootID(u.Uid)
	if err != nil {
		return 1, err
	}
	gid, err := nonRootID(u.Gid)
	if err != nil {
		return 1, err
	}
	home := u.HomeDir
	if !filepath.IsAbs(home) || filepath.Clean(home) != home || home == "/" {
		return 1, errors.New("workload account requires an absolute home directory other than /")
	}
	// Re-enter cwd *after* setuid, so inaccessible ancestor directories aren't
	// bypassed by simply inheriting root's directory handle. Don't trust $PWD.
	cwd, err := os.Readlink("/proc/self/cwd")
	if err != nil {
		return 1, err
	}
	attr := &syscall.ProcAttr{
		Dir:   cwd,
		Files: []uintptr{0, 1, 2},
		Env: []string{
			"HOME=" + home, "PATH=/usr/local/bin:/usr/bin:/bin",
			"USER=" + u.Username, "LOGNAME=" + u.Username, "LANG=C",
			"GIT_CONFIG_NOSYSTEM=1", "GIT_TERMINAL_PROMPT=0",
		},
		Sys: &syscall.SysProcAttr{
			Credential: &syscall.Credential{Uid: uid, Gid: gid}, // setgroups(0)
			Setsid:     true, Ptrace: true, Pdeathsig: syscall.SIGKILL,
		},
	}
	// ptrace is owned by one Linux task, not by the tracer's thread group.
	// Retire this thread on return. Even if cleanup itself failed, EXITKILL
	// is then delivered rather than leaving live tracees on a pooled thread.
	type result struct {
		code int
		err  error
	}
	done := make(chan result)
	go func() {
		runtime.LockOSThread() // intentionally no UnlockOSThread
		pid, err := syscall.ForkExec("/proc/self/exe", append([]string{"agent-smith", bootstrapArg}, argv...), attr)
		if err != nil {
			done <- result{1, fmt.Errorf("start unprivileged bootstrap: %w", err)}
			return
		}
		code, err := trace(pid, uid, rules, emit)
		done <- result{code, err}
	}()
	r := <-done
	return r.code, r.err
}

func nonRootID(s string) (uint32, error) {
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil || n == 0 || n == 0xffffffff {
		return 0, errors.New("workload requires a non-root UID and primary GID")
	}
	return uint32(n), nil
}

// Check the account's persistent home only after dropping privileges. Require
// trusted parents so another local account can't replace it after validation.
func checkHome(home string) error {
	if !filepath.IsAbs(home) || filepath.Clean(home) != home || home == "/" {
		return errors.New("invalid workload home")
	}
	for p := home; ; p = filepath.Dir(p) {
		var st unix.Stat_t
		if err := unix.Lstat(p, &st); err != nil {
			return fmt.Errorf("stat workload home or ancestor: %w", err)
		}
		wantUID := uint32(0)
		if p == home {
			wantUID = uint32(os.Geteuid())
		}
		if st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != wantUID || st.Mode&0022 != 0 {
			return errors.New("workload home must be user-owned under root-owned directories, without symlinks or shared write access")
		}
		if p == "/" {
			break
		}
	}
	return unix.Access(home, unix.W_OK|unix.X_OK)
}

// BootstrapIfRequested is invoked during initialization of the same trusted
// executable re-exec'd by Run. This is never a privileged entry point.
func BootstrapIfRequested() {
	if len(os.Args) < 2 || os.Args[1] != bootstrapArg {
		return
	}
	if err := bootstrap(os.Args[2:]); err != nil {
		fmt.Fprintf(os.Stderr, "agent-smith bootstrap: %v\n", err)
	}
	os.Exit(125)
}

func bootstrap(argv []string) error {
	if os.Getuid() == 0 || os.Geteuid() == 0 || os.Getgid() == 0 || os.Getegid() == 0 || len(argv) == 0 || !filepath.IsAbs(argv[0]) {
		return errors.New("invalid non-root bootstrap invocation")
	}
	groups, err := os.Getgroups()
	if err != nil || len(groups) != 0 {
		return errors.New("supplementary groups not cleared")
	}
	if err := checkHome(os.Getenv("HOME")); err != nil {
		return err
	}
	runtime.LockOSThread() // settings below apply to the task that calls execve
	defer runtime.UnlockOSThread()
	unix.Umask(0077)
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("set no_new_privs: %w", err)
	}
	var caps [2]unix.CapUserData
	if err := unix.Capset(&unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}, &caps[0]); err != nil {
		return fmt.Errorf("clear capabilities: %w", err)
	}
	// Disconnect the parent's session keyring. ENOSYS means no keyring API.
	if _, _, e := unix.Syscall6(unix.SYS_KEYCTL, unix.KEYCTL_JOIN_SESSION_KEYRING, 0, 0, 0, 0, 0); e != 0 && e != unix.ENOSYS {
		return fmt.Errorf("replace session keyring: %w", e)
	}
	// Go's child setup does not close arbitrary non-CLOEXEC FDs in the
	// launching process. Unshare our table and atomically close these at exec.
	if err := unix.CloseRange(3, 0xffffffff, unix.CLOSE_RANGE_UNSHARE|unix.CLOSE_RANGE_CLOEXEC); err != nil {
		return fmt.Errorf("seal file descriptors: %w", err)
	}
	if err := installFilter(); err != nil {
		return fmt.Errorf("install workload filter: %w", err)
	}
	// The trusted runtime's other threads are destroyed by this exec. Only
	// this thread's no_new_privs, fd table, and seccomp policy survive.
	return unix.Exec(argv[0], argv, os.Environ())
}
