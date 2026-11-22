//go:build linux && (amd64 || arm64)

package supervisor

import (
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Install an inherited seccomp filter before any workload code is allowed to
// run. Checking legacy clone's scalar flags in the kernel avoids races reading
// tracee memory. clone3's pointer-based API is disabled (with libc fallback).
func installFilter() error {
	arch := uint32(unix.AUDIT_ARCH_X86_64)
	if runtime.GOARCH == "arm64" {
		arch = unix.AUDIT_ARCH_AARCH64
	}
	const (
		load   = unix.BPF_LD | unix.BPF_W | unix.BPF_ABS
		equals = unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K
		bits   = unix.BPF_JMP | unix.BPF_JSET | unix.BPF_K
		ret    = unix.BPF_RET | unix.BPF_K
		forbid = unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)
		// Both supported architectures have little-endian seccomp_data:
		// s32 nr @ 0, u32 arch @ 4, u64 args[0] @ 16.
		badClone = unix.CLONE_UNTRACED | unix.CLONE_PARENT | unix.CLONE_NEWUSER |
			unix.CLONE_NEWNS | unix.CLONE_NEWNET | unix.CLONE_NEWPID | unix.CLONE_NEWUTS |
			unix.CLONE_NEWCGROUP | unix.CLONE_NEWIPC | unix.CLONE_NEWTIME
	)
	filter := []unix.SockFilter{
		{Code: load, K: 4},
		{Code: equals, K: arch, Jt: 1},
		{Code: ret, K: unix.SECCOMP_RET_KILL_PROCESS},
		{Code: load, K: 0},
		// x86's x32 ABI shares AUDIT_ARCH_X86_64 but not syscall numbers.
		{Code: bits, K: 0x40000000, Jf: 1},
		{Code: ret, K: unix.SECCOMP_RET_KILL_PROCESS},
		{Code: equals, K: unix.SYS_CLONE3, Jf: 1},
		{Code: ret, K: unix.SECCOMP_RET_ERRNO | uint32(unix.ENOSYS)},
		{Code: equals, K: unix.SYS_CLONE, Jf: 4},
		{Code: load, K: 16},
		{Code: bits, K: badClone, Jf: 1},
		{Code: ret, K: forbid},
		{Code: ret, K: unix.SECCOMP_RET_ALLOW},
	}
	for _, nr := range []uint32{
		// Keep descendants inside their original private process group.
		unix.SYS_SETSID, unix.SYS_SETPGID, unix.SYS_UNSHARE, unix.SYS_SETNS,
		unix.SYS_SETUID, unix.SYS_SETREUID, unix.SYS_SETRESUID, unix.SYS_SETFSUID,
		unix.SYS_SETGID, unix.SYS_SETREGID, unix.SYS_SETRESGID, unix.SYS_SETFSGID,
		unix.SYS_SETGROUPS, unix.SYS_CAPSET, unix.SYS_CHROOT, unix.SYS_MOUNT,
		unix.SYS_PTRACE, unix.SYS_PROCESS_VM_WRITEV, unix.SYS_PIDFD_GETFD,
		unix.SYS_KEYCTL, unix.SYS_ADD_KEY, unix.SYS_REQUEST_KEY,
		unix.SYS_IO_URING_SETUP, unix.SYS_IO_URING_ENTER, unix.SYS_IO_URING_REGISTER,
	} {
		filter = append(filter, unix.SockFilter{Code: equals, K: nr, Jf: 1}, unix.SockFilter{Code: ret, K: forbid})
	}
	filter = append(filter, unix.SockFilter{Code: ret, K: unix.SECCOMP_RET_ALLOW})
	prog := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	_, _, errno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, 0, uintptr(unsafe.Pointer(&prog)))
	runtime.KeepAlive(filter)
	if errno != 0 {
		return errno
	}
	return nil
}
