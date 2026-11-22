package watch

import (
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/brunoborges/agent-smith/internal/policy"
	"golang.org/x/sys/unix"
)

func Run(r io.Reader, host policy.Host, emit policy.Emit) error {
	if r == nil || emit == nil {
		return errors.New("watch requires an input stream and event sink")
	}
	var respond responder
	if host.Armed {
		if s := verifiedSource(r); s != nil {
			defer unix.Close(s.clockFD)
			respond = func(e evidence) string {
				return s.respond(e, host.ProtectedExes)
			}
		}
	}
	return consume(r, host, emit, respond, time.Now)
}

type source struct {
	parent  int
	lost    uint32
	clockFD int
	hz      int64
	minUID  uint32
	maxUID  uint32
	invalid bool
}

func readSmall(path string, limit int64) (string, bool) {
	f, err := os.Open(path)
	if err != nil {
		return "", false
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	return string(b), err == nil && int64(len(b)) <= limit
}

func proc(pid int, file string) string {
	return "/proc/" + strconv.Itoa(pid) + "/" + file
}

func same(a, b string) bool {
	x, e1 := os.Stat(a)
	y, e2 := os.Stat(b)
	return e1 == nil && e2 == nil && os.SameFile(x, y)
}

func rootOwned(path string) bool {
	file := true
	for {
		var s unix.Stat_t
		if unix.Lstat(path, &s) != nil || s.Uid != 0 || s.Mode&022 != 0 ||
			(file && s.Mode&unix.S_IFMT != unix.S_IFREG) || (!file && s.Mode&unix.S_IFMT != unix.S_IFDIR) {
			return false
		}
		if path == "/" {
			return true
		}
		path, file = filepath.Dir(path), false
	}
}

// These fixed initial namespace inode numbers are Linux UAPI conventions
// (include/linux/proc_ns.h). Merely comparing with /proc/1 is insufficient:
// in a container PID 1 is not necessarily the host's init.
func initialNamespaces() bool {
	var fs unix.Statfs_t
	if unix.Statfs("/proc", &fs) != nil || fs.Type != unix.PROC_SUPER_MAGIC || !same("/proc/self", proc(os.Getpid(), "")) {
		return false
	}
	for ns, ino := range map[string]uint64{"pid": 0xeffffffc, "user": 0xeffffffd, "cgroup": 0xeffffffb, "time": 0xeffffffa} {
		var s unix.Stat_t
		path := "/proc/self/ns/" + ns
		if unix.Stat(path, &s) != nil || s.Ino != ino || !same(path, "/proc/1/ns/"+ns) {
			return false
		}
	}
	return same("/proc/self/ns/mnt", "/proc/1/ns/mnt") && same("/proc/self/root", "/proc/1/root")
}

func configValues(path string) (map[string]string, bool) {
	if !rootOwned(path) {
		return nil, false
	}
	b, ok := readSmall(path, 64*1024)
	if !ok {
		return nil, false
	}
	values := make(map[string]string)
	for _, line := range strings.Split(b, "\n") {
		line, _, _ = strings.Cut(line, "#")
		f := strings.Fields(strings.ReplaceAll(line, "=", " "))
		if len(f) == 0 {
			continue
		}
		k := strings.ToLower(f[0])
		switch k {
		case "uid_min", "uid_max", "tcp_listen_port", "distribute_network", "name_format", "log_format":
			if _, dup := values[k]; len(f) != 2 || dup {
				return nil, false
			}
			values[k] = strings.ToLower(f[1])
		}
	}
	return values, true
}

// The root kernel netlink reply (not /run/auditd.pid or a process name)
// identifies the actual audit daemon and the kernel loss counter. Read-only
// AUDIT_GET; no registration, audit rules, or audit settings are changed.
func auditStatus() (pid int, lost uint32, ok bool) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.NETLINK_AUDIT)
	if err != nil {
		return
	}
	defer unix.Close(fd)
	var msg [unix.NLMSG_HDRLEN]byte
	binary.NativeEndian.PutUint32(msg[0:], uint32(len(msg)))
	binary.NativeEndian.PutUint16(msg[4:], unix.AUDIT_GET)
	binary.NativeEndian.PutUint16(msg[6:], unix.NLM_F_REQUEST)
	binary.NativeEndian.PutUint32(msg[8:], 1)
	if unix.Sendto(fd, msg[:], 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}) != nil {
		return
	}
	if n, err := unix.Poll([]unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}, 150); n != 1 || err != nil {
		return
	}
	var buf [4096]byte
	n, from, err := unix.Recvfrom(fd, buf[:], 0)
	addr, valid := from.(*unix.SockaddrNetlink)
	if err != nil || !valid || addr.Pid != 0 || addr.Groups != 0 {
		return
	}
	replies, err := syscall.ParseNetlinkMessage(buf[:n])
	if err != nil || len(replies) != 1 {
		return
	}
	m := replies[0]
	if m.Header.Type != unix.AUDIT_GET || m.Header.Seq != 1 || len(m.Data) < 32 || binary.NativeEndian.Uint32(m.Data[4:]) == 0 {
		return
	}
	return int(binary.NativeEndian.Uint32(m.Data[12:])), binary.NativeEndian.Uint32(m.Data[24:]), true
}

func verifiedSource(r io.Reader) *source {
	f, ok := r.(*os.File)
	if !ok || f.Fd() != 0 || os.Geteuid() != 0 || !initialNamespaces() {
		return nil
	}
	parent := os.Getppid()
	peer, err := unix.GetsockoptUcred(0, unix.SOL_SOCKET, unix.SO_PEERCRED)
	domain, e1 := unix.GetsockoptInt(0, unix.SOL_SOCKET, unix.SO_DOMAIN)
	typ, e2 := unix.GetsockoptInt(0, unix.SOL_SOCKET, unix.SO_TYPE)
	if err != nil || e1 != nil || e2 != nil || parent <= 1 || int(peer.Pid) != parent ||
		peer.Uid != 0 || domain != unix.AF_UNIX || typ != unix.SOCK_STREAM {
		return nil
	}
	exe, err := os.Readlink(proc(parent, "exe"))
	cg, _ := readSmall(proc(parent, "cgroup"), 4096)
	if err != nil || (exe != "/usr/sbin/auditd" && exe != "/sbin/auditd") || !rootOwned(exe) ||
		!same(exe, proc(parent, "exe")) || cg != "0::/system.slice/auditd.service\n" {
		return nil
	}
	args, ok := readSmall(proc(parent, "cmdline"), 4096)
	if !ok || len(args) == 0 {
		return nil
	}
	for _, a := range strings.Split(strings.TrimSuffix(args, "\x00"), "\x00")[1:] {
		// In particular reject alternate config directories and aggregation mode.
		if a != "-n" && a != "-f" {
			return nil
		}
	}
	cfg, ok := configValues("/etc/audit/auditd.conf")
	if !ok || (cfg["tcp_listen_port"] != "" && cfg["tcp_listen_port"] != "0") ||
		(cfg["distribute_network"] != "" && cfg["distribute_network"] != "no") ||
		(cfg["name_format"] != "" && cfg["name_format"] != "none") || cfg["log_format"] != "raw" {
		return nil
	}
	defs, ok := configValues("/etc/login.defs")
	lo, e1 := strconv.ParseUint(defs["uid_min"], 10, 32)
	hi, e2 := strconv.ParseUint(defs["uid_max"], 10, 32)
	if !ok || e1 != nil || e2 != nil || lo > hi {
		return nil
	}
	pid, lost, ok := auditStatus()
	// auditd starts plugins just before registering itself on a cold boot.
	if !ok || (pid != 0 && pid != parent) {
		return nil
	}
	hz := clockTicks()
	if hz <= 0 {
		return nil
	}
	fd, err := unix.TimerfdCreate(unix.CLOCK_REALTIME, unix.TFD_CLOEXEC|unix.TFD_NONBLOCK)
	if err != nil {
		return nil
	}
	timer := unix.ItimerSpec{Value: unix.NsecToTimespec(time.Now().AddDate(1, 0, 0).UnixNano())}
	if unix.TimerfdSettime(fd, unix.TFD_TIMER_ABSTIME|unix.TFD_TIMER_CANCEL_ON_SET, &timer, nil) != nil {
		unix.Close(fd)
		return nil
	}
	return &source{parent: parent, lost: lost, clockFD: fd, hz: hz, minUID: uint32(max(lo, 1000)), maxUID: uint32(min(hi, 60000))}
}

func clockTicks() int64 {
	aux, ok := readSmall("/proc/self/auxv", 8192)
	if !ok || strconv.IntSize != 64 {
		return 0
	}
	for b := []byte(aux); len(b) >= 16; b = b[16:] {
		if binary.NativeEndian.Uint64(b) == 17 { // getauxval(AT_CLKTCK)
			hz := binary.NativeEndian.Uint64(b[8:])
			if hz >= 10 && hz <= 10000 {
				return int64(hz)
			}
		}
	}
	return 0
}
