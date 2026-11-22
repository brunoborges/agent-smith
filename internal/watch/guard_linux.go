package watch

import (
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

type taskStat struct {
	parent int
	start  int64
}

func task(pid int) (taskStat, bool) {
	b, ok := readSmall(proc(pid, "stat"), 4096)
	// comm can contain spaces, parentheses, or even newlines.
	end := strings.LastIndexByte(b, ')')
	if !ok || end == -1 || !strings.HasPrefix(b, strconv.Itoa(pid)+" (") {
		return taskStat{}, false
	}
	f := strings.Fields(b[end+1:])
	if len(f) < 20 || f[0] == "Z" || f[0] == "X" {
		return taskStat{}, false
	}
	p, e1 := strconv.ParseUint(f[1], 10, 31)
	t, e2 := strconv.ParseInt(f[19], 10, 64)
	return taskStat{int(p), t}, e1 == nil && e2 == nil && t > 0
}

func outsideAncestry(pid int) bool {
	for p, hops := os.Getpid(), 0; hops < 128 && p > 0; hops++ {
		if p == pid {
			return false
		}
		if p == 1 {
			return true
		}
		st, ok := task(p)
		if !ok {
			return false
		}
		p = st.parent
	}
	return false
}

func sessionScope(s, uid string) bool {
	s, ok := strings.CutPrefix(s, "0::/user.slice/user-"+uid+".slice/session-")
	s, suffix := strings.CutSuffix(s, ".scope\n")
	if !ok || !suffix {
		return false
	}
	n, err := strconv.ParseUint(s, 10, 32)
	return err == nil && n != 0 && strconv.FormatUint(n, 10) == s
}

func safeStatus(s, uid string, pid, tid int) bool {
	f := make(map[string][]string)
	for _, line := range strings.Split(s, "\n") {
		k, v, ok := strings.Cut(line, ":")
		if ok {
			f[k] = strings.Fields(v)
		}
	}
	wanted := map[string]string{
		"Tgid": strconv.Itoa(pid), "NSpid": strconv.Itoa(tid), "TracerPid": "0",
	}
	for k, v := range wanted {
		if len(f[k]) != 1 || f[k][0] != v {
			return false
		}
	}
	for _, k := range []string{"CapInh", "CapPrm", "CapEff", "CapAmb"} {
		if len(f[k]) != 1 || f[k][0] != "0000000000000000" {
			return false
		}
	}
	g := f["Gid"]
	if len(g) != 4 || g[0] == "0" || g[0] != g[1] || g[0] != g[2] || g[0] != g[3] {
		return false
	}
	u := f["Uid"]
	return len(u) == 4 && u[0] == uid && u[1] == uid && u[2] == uid && u[3] == uid
}

func threadSet(pid int) ([]string, bool) {
	const maxThreads = 256
	d, err := os.Open(proc(pid, "task"))
	if err != nil {
		return nil, false
	}
	defer d.Close()
	names, err := d.Readdirnames(maxThreads + 1)
	if (err != nil && err != io.EOF) || len(names) == 0 || len(names) > maxThreads {
		return nil, false
	}
	slices.Sort(names)
	return names, true
}

func safeThreads(p int, uid string, when time.Time) bool {
	before, ok := threadSet(p)
	if !ok {
		return false
	}
	for _, name := range before {
		tid, err := strconv.Atoi(name)
		if err != nil || tid <= 0 || !fresh(when, time.Now()) {
			return false
		}
		base := proc(p, "task/"+name+"/")
		status, ok := readSmall(base+"status", 16*1024)
		if !ok || !safeStatus(status, uid, p, tid) {
			return false
		}
		cg, ok := readSmall(base+"cgroup", 4096)
		login, okLogin := readSmall(base+"loginuid", 32)
		if !ok || !sessionScope(cg, uid) || !okLogin || strings.TrimSpace(login) != uid {
			return false
		}
		for _, n := range []string{"pid", "user", "mnt", "cgroup", "net", "time"} {
			if !same(base+"ns/"+n, "/proc/1/ns/"+n) {
				return false
			}
		}
		if !same(base+"root", "/proc/1/root") {
			return false
		}
	}
	after, ok := threadSet(p)
	return ok && slices.Equal(before, after)
}

func infra(exe string, protected []string) bool {
	for _, path := range protected {
		if path == exe || same(path, exe) {
			return true
		}
	}
	name := filepath.Base(exe)
	if strings.HasPrefix(name, "systemd") || strings.HasPrefix(name, "dbus-") ||
		strings.HasPrefix(name, "sshd") || strings.HasPrefix(name, "audit") {
		return true
	}
	switch name {
	case "init", "agent-smith", "login", "agetty", "polkitd", "sudo", "su", "cron", "crond", "ssh-agent", "gpg-agent",
		"rsyslogd", "journald", "containerd", "dockerd", "kubelet", "NetworkManager":
		return true
	}
	return same(exe, "/proc/self/exe") || same(exe, "/proc/1/exe")
}

func liveIdentity(e evidence, protected []string) bool {
	uid := strconv.FormatUint(uint64(e.UID), 10)
	p := e.pid
	if !safeThreads(p, uid, e.when) {
		return false
	}
	// Recheck leader credentials, scope and executable after the thread walk.
	status, ok := readSmall(proc(p, "status"), 16*1024)
	cg, cgOK := readSmall(proc(p, "cgroup"), 4096)
	if !ok || !safeStatus(status, uid, p, p) || !cgOK || !sessionScope(cg, uid) {
		return false
	}
	exe := proc(p, "exe")
	path, err := os.Readlink(exe)
	if err != nil || path != e.Exe || strings.HasSuffix(path, " (deleted)") || !same(exe, path) || infra(path, protected) {
		return false
	}
	if e.Kind == "exec" {
		cmd, ok := readSmall(proc(p, "cmdline"), 32*1024)
		if !ok || len(e.Argv) == 0 || cmd != strings.Join(e.Argv, "\x00")+"\x00" {
			return false
		}
		var st unix.Stat_t
		if unix.Stat(exe, &st) != nil {
			return false
		}
		ident := fileID{uint64(unix.Major(st.Dev)), uint64(unix.Minor(st.Dev)), st.Ino}
		for _, candidate := range e.paths {
			if ident == candidate {
				return true
			}
		}
		return false
	}
	return e.Kind == "connect"
}

// stat.starttime is quantized in USER_HZ ticks since boot, not wall time.
// Use the *upper* edge of the tick and bracket it with BOOTTIME then
// REALTIME; same-tick or uncertain results must not be treated as proof.
func latestStart(ticks, hz int64) (time.Time, bool) {
	var boot unix.Timespec
	if hz < 10 || hz > 10000 || ticks < 1 || unix.ClockGettime(unix.CLOCK_BOOTTIME, &boot) != nil {
		return time.Time{}, false
	}
	now := time.Now()
	if ticks/hz > boot.Sec {
		return time.Time{}, false
	}
	ns := (ticks/hz)*1e9 + ((ticks%hz+1)*1e9+hz-1)/hz
	return now.Add(time.Duration(ns-boot.Nano()) + 10*time.Millisecond), true
}

func matchesStart(st taskStat, hz int64, e evidence) bool {
	start, measured := latestStart(st.start, hz)
	return measured && st.parent == e.ppid && start.Before(e.when)
}

func (s *source) respond(e evidence, protected []string) string {
	if s.invalid {
		return "disarmed"
	}
	auditPID, lost, ok := auditStatus()
	if !ok || auditPID != s.parent || os.Getppid() != s.parent || lost != s.lost {
		s.invalid = true
		return "audit-status-changed"
	}
	if !e.credsOK || e.UID < s.minUID || e.UID > s.maxUID || e.pid <= 1 || !outsideAncestry(e.pid) {
		return "guarded"
	}
	fd, err := unix.PidfdOpen(e.pid, 0)
	if err != nil {
		return "guarded"
	}
	defer unix.Close(fd)
	st, ok := task(e.pid)
	if !ok || !matchesStart(st, s.hz, e) {
		return "guarded"
	}
	// The open pidfd will never signal a replacement, even if a procfs read
	// races with exit. Recheck mutable fields as late as practical.
	if !liveIdentity(e, protected) {
		return "guarded"
	}
	last, ok := task(e.pid)
	if !ok || last != st {
		return "guarded"
	}
	var b [8]byte
	if _, err := unix.Read(s.clockFD, b[:]); err != unix.EAGAIN {
		// A wall-clock step invalidates comparisons with audit timestamps.
		s.invalid = true
		return "clock-discontinuity"
	}
	if !fresh(e.when, time.Now()) {
		return "stale"
	}
	if unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0) != nil {
		return "signal-failed"
	}
	return "signal-sent"
}
