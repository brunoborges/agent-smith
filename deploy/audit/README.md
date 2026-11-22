# Local audit dispatcher watchdog

Use on a **dedicated Linux host**, with an operator-managed, root-owned policy
and a nonprivileged workload account. This observes completed kernel audit
events. It cannot veto an exec, connection, command, or transfer before it
happens. A `signal-sent` event means the kernel accepted SIGKILL; it does not
mean the original action was prevented or undone.

## Report-only rollout

1. Start in a disposable VM with local auditd 3.x/4.x, native x86-64 or
   AArch64 syscalls, and a root-owned `/usr/local/sbin/agent-smith`. Keep
   `host.armed` **false**. Put the validated policy at
   `/etc/agent-smith/policy.json`. The CLI writes JSON events to the private
   root-owned `/var/log/agent-smith.jsonl`; **verify** it receives matches.
2. Adapt [`65-agent-smith.rules`](65-agent-smith.rules) to the **actual EUID**
   of the workload. Duplicate those two rules for other enrolled UIDs, if
   needed. Keep the two keys unchanged. Review rule ordering and any `never`
   rules with the audit administrator. The sample does not change global
   audit settings or collect host-wide activity. Other ABIs, 32-bit socketcall,
   UDP `sendto`, io_uring, or events outside these filters are not covered.
3. The dispatcher needs local events, `log_format = RAW`, `name_format = none`,
   no network aggregation (`tcp_listen_port` unset/0; `distribute_network = no`).
   Install [`agent-smith.conf`](agent-smith.conf) under `/etc/audit/plugins.d/`,
   then explicitly set `active = yes` when ready to **observe**. Use your
   distribution's supported audit rule load and daemon restart procedure.
   Check `auditctl -l`, `auditctl -s`, auditd logs and dispatcher queue health.
   Audit rules and auditd's **own** raw logs include potentially sensitive
   argv/paths/addresses. Restrict access and retention. Watch emits only policy
   IDs, categories, PID/UID, timestamps and fixed outcomes.
4. Exercise benign matching and nonmatching commands and numeric network
   destinations. Verify output from the **live plugin**, not just a replay of
   `audit.log`. In particular: auditd normally forwards `EOE` to plugins but
   does not write it to the local log. No EOE means **no response**.
   Do not wrap the plugin, feed it with `tail`, or expose a socket/API to users.

## Before considering a kill rule

Both `host.armed: true` **and** a matching `action: "kill"` are required.
Root CLI admission alone is **not** sufficient. Only the real stdin AF_UNIX
stream socketpair of the directly spawning, root-owned system auditd on the
initial host namespaces can arm. Kernel `AUDIT_GET` must identify the parent
at action time. Logs, pipes, named sockets supplied by clients, shell
wrappers, remote or node-prefixed records and enriched records cannot arm.
For enriched local input, only the raw prefix is considered for reporting;
interpreted fields never override kernel values.
No legacy standalone `audispd`, alternate config directory, unsupported
namespace layout, or cgroup-v1 fallback. Use a real local procfs, cgroup v2
and the standard `/system.slice/auditd.service`. The audit daemon must be
allowed to query audit status, read procfs, open pidfds and signal an eligible
target. Do not loosen an existing service sandbox merely to force arming.

Live targets must be **nonprivileged workloads in an actual
`user.slice/user-UID.slice/session-N.scope` login session**, with login,
real, effective, saved and filesystem UIDs all the same regular UID
(`/etc/login.defs` UID_MIN..UID_MAX, further limited to 1000..60000). They
must have no effective/permitted/inheritable/ambient capabilities and share
host namespaces and root. The responder checks these properties for every
thread and compares the thread set before and after validation (up to 256
threads; concurrent churn or more threads means flag only). This **excludes**
services, including user services, containerized workloads and systemd units
running as high-numbered service users. PID 1, the watchdog, its ancestors,
known infrastructure, and executables in `host.protected_exes` are protected.
Add all site-specific infrastructure paths there. Unsupported, ambiguous,
already-exited, privileged or stale targets are not signaled. There is no
`kill(pid, ...)` fallback.

The audit EUID, executable, parent PID and timestamp must agree with live
procfs checks after opening a pidfd. For exec records the executable must
also match a recorded PATH device/inode and the entire live cmdline must
still agree. Audit resolution and USER_HZ rounding mean a just-forked process
may be too new to distinguish from PID reuse: **flag it**, do not relax the
time check. A pidfd never retargets a replacement PID. Linux has no atomic
“signal only if exe/UID/cgroup still matches” syscall: an already-identified
task could change its own state after validation. Do not use this retrospective
watchdog where that residual race, or missed short-lived processes, is
unacceptable.

## Health, bounds and rollback

Only local, newline-framed `SYSCALL`, `EXECVE`, `PATH`, `SOCKADDR`, `EOE`
records with matching timestamp **and** serial form observations. Scope keys
select native exec/execveat and connect (including nonblocking/failed
attempts); no command-line or destination text matching across raw lines.
Limits: 16 KiB/line, 128 concurrent events, 32 KiB and 64 relevant records per
event, 128 arguments. Chunked/oversized arguments are not guessed. A matching
event must be younger than two seconds at signal time and newer than plugin
startup. Incomplete/stale records are never used to signal. Partial groups
expire on subsequent traffic and are flushed at EOF; memory remains bounded
when idle. Not all kernel/dispatcher loss is observable in the stream.
Monitor kernel `lost`, backlog and plugin drops independently. A detected
kernel loss counter change, clock step, malformed stream, overflow or explicit
loss disables signaling for this invocation. Investigate redacted health
events and restart the plugin from auditd after correcting the cause.

Rollback: set `host.armed` false and restart/reload the plugin using approved
service procedures (config is read at startup). Set `active = no` to stop
observing. Remove **only** the site-installed scoped rules using the distro's
audit rules mechanism. Do not flush all host rules; immutable audit modes may
require a scheduled reboot.
