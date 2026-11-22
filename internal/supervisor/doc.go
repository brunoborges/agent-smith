// Package supervisor is a Linux exec gate for one enrolled process tree, not
// a network or filesystem sandbox. It requires a trusted kernel (5.11+), procfs,
// root with ptrace/credential/signal permissions, and a dedicated, otherwise
// unused workload account. Only stdio and working directory come from the
// caller. Supply safe stdio and a cwd the workload account can re-enter.
//
// Rules inspect the kernel-selected executable and committed argv at the exec
// stop, before userspace resumes. They do not identify Git operations performed
// in-process, by other services, under renamed binaries, or via Git aliases or
// alternate protocols. Use read-only repository credentials independently.
//
// Filters restrict namespace/process-group changes and untraced clone paths.
// Job control, detached sessions, supplementary groups and non-native syscall
// ABIs are not supported. The supervisor waits for descendants that outlive
// the root; a matching kill terminates only the matching process. Integrity
// or event-sink failures terminate the entire private process group.
package supervisor
