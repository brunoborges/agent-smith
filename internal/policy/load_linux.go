package policy

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// Load opens relative to verified directory fds, never following symlinks.
func Load(filename string) (*Config, error) {
	if !absolute(filename) {
		return nil, errors.New("policy filename must be absolute and clean")
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	dir := os.NewFile(uintptr(fd), "/")
	defer func() { dir.Close() }()
	parts := strings.Split(filename[1:], "/")
	for i, part := range parts {
		last := i == len(parts)-1
		flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK
		if !last {
			flags |= unix.O_DIRECTORY
		}
		fd, err := unix.Openat(int(dir.Fd()), part, flags, 0)
		if err != nil {
			return nil, fmt.Errorf("open policy component %q: %w", part, err)
		}
		dir.Close()
		dir = os.NewFile(uintptr(fd), part)
		var st unix.Stat_t
		if err := unix.Fstat(fd, &st); err != nil {
			return nil, err
		}
		if st.Uid != 0 || st.Mode&0022 != 0 || (last && st.Mode&unix.S_IFMT != unix.S_IFREG) {
			return nil, fmt.Errorf("untrusted policy component %q: require root ownership, no group/other write and a regular policy file", part)
		}
	}
	return decode(dir)
}
