package explain

import (
	"errors"
	"os"
	"os/user"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

const analyst = "agent-smith-analyst"

func requireAnalyst() error {
	denied := errors.New("explain: requires a direct login as the dedicated non-root agent-smith-analyst account, without capabilities or supplementary groups")
	uid, gid := os.Getuid(), os.Getgid()
	if uid <= 0 || gid <= 0 || os.Geteuid() != uid || os.Getegid() != gid {
		return denied
	}
	account, err := user.Lookup(analyst)
	if err != nil || account.Uid != strconv.Itoa(uid) || account.Gid != strconv.Itoa(gid) {
		return denied
	}
	status, err := os.ReadFile("/proc/self/status")
	if err != nil || !ordinaryIdentity(string(status), account.Uid, account.Gid) || !noInheritedFDs() {
		return denied
	}
	// No elevated launcher or customizable image. Administrators must also
	// keep the image contents (not just its top directory) trusted.
	for _, path := range []string{"/usr", "/usr/bin", bwrap, "/opt", "/opt/agent-smith", rootfs} {
		info, err := os.Lstat(path)
		if err != nil || info.Sys().(*syscall.Stat_t).Uid != 0 ||
			info.Mode()&(os.ModeSymlink|os.ModeSetuid|os.ModeSetgid|0022) != 0 ||
			(path == bwrap && !info.Mode().IsRegular()) || (path != bwrap && !info.IsDir()) {
			return errors.New("explain: missing or unsafe system bubblewrap/runtime installation; see docs/explain.md")
		}
	}
	if _, err := unix.Getxattr(bwrap, "security.capability", nil); !errors.Is(err, unix.ENODATA) && !errors.Is(err, unix.ENOTSUP) {
		return errors.New("explain: requires bubblewrap without file capabilities")
	}
	return nil
}

// An unexpected inherited descriptor could be an open workspace directory,
// privileged socket or credential, independent of filesystem isolation.
func noInheritedFDs() bool {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return false
	}
	for _, entry := range entries {
		fd, err := strconv.Atoi(entry.Name())
		if err != nil {
			return false
		}
		if fd > 2 {
			flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
			if !errors.Is(err, unix.EBADF) && (err != nil || flags&unix.FD_CLOEXEC == 0) {
				return false
			}
		}
	}
	return true
}

func ordinaryIdentity(status, uid, gid string) bool {
	seen := 0
	for _, line := range strings.Split(status, "\n") {
		key, rest, _ := strings.Cut(line, ":")
		vals := strings.Fields(rest)
		switch key {
		case "Uid", "Gid":
			want := uid
			if key == "Gid" {
				want = gid
			}
			if len(vals) != 4 {
				return false
			}
			for _, v := range vals { // real, effective, saved and filesystem IDs
				if v != want {
					return false
				}
			}
		case "Groups":
			for _, v := range vals {
				if v != gid {
					return false
				}
			}
		case "CapInh", "CapPrm", "CapEff", "CapAmb":
			if len(vals) != 1 || strings.Trim(vals[0], "0") != "" {
				return false
			}
		default:
			continue
		}
		seen++
	}
	return seen == 7
}
