# Agent Smith

Agent Smith is a Linux process watchdog for a dedicated agent host. It has two enforcement paths:

| Command | What it can do |
| --- | --- |
| `run` | Launch an unprivileged workload under a root supervisor. Inspect executable launches in its process tree and stop a forbidden command **before the new program runs**. |
| `watch` | Consume the host's Linux Audit stream, including activity from processes Smith didn't launch. Flag configured behavior or, when explicitly armed, signal a still-identifiable, unprotected process. **This is detection and response**, not prevention or rollback. |
| [`explain`](docs/explain.md) | Ask Copilot, Claude, or Codex to explain an event as a non-root user. Explanations never authorize signals, change policy, or delay enforcement. |

## Run a review-only agent

On native amd64 or arm64 Linux (kernel 5.11+ for the launcher's `close_range` flags), with Go 1.23+, procfs, ptrace and seccomp enabled:

```sh
go build -o agent-smith ./cmd/agent-smith
sudo install -o root -g root -m 0755 agent-smith /usr/local/sbin/agent-smith
sudo install -d -o root -g root -m 0755 /etc/agent-smith
sudo install -o root -g root -m 0600 examples/policy.json /etc/agent-smith/policy.json
```

Provision a dedicated non-root account (e.g. `reviewer`) with access to the checkout and its own provider login. **Give it only read-only remote credentials.** For GitHub, for example, use a repository-scoped read-only deploy key rather than a developer's SSH agent or a token with Contents write permission. Do not grant the account sudo, access to a container daemon, a write-capable credential helper, or access to other users' credentials. Authentication to a coding assistant does not by itself make its repository access read-only.

From a checkout accessible to the reviewer, start the desired CLI:

```sh
sudo agent-smith run --profile review --user reviewer --provider copilot -- -p 'Review the current diff'
sudo agent-smith run --profile review --user reviewer --provider claude -- -p 'Review the current diff'
sudo agent-smith run --profile review --user reviewer --provider codex -- exec 'Review the current diff'
```

Smith finds provider CLIs in `/usr/local/bin`, `/usr/bin`, or `/bin`. Put provider arguments after `--`, or supply an absolute executable instead of a provider. The same policy applies to ordinary programs:

```sh
sudo agent-smith run --profile review --user reviewer -- /usr/bin/git diff
```

With the example `review` profile, `git diff` runs normally. If the reviewer starts `git push`, even through a shell or with `git -C <dir> push`, Smith kills the Git process, not every process owned by that user. The parent agent may continue working. Smith records local decisions in `/var/log/agent-smith.jsonl` (root-only).

`run` is intended for non-interactive commands, with a fresh session, the reviewer's own home and a clean environment. Its inherited security filter restricts process-group changes, new namespaces, debugger attachment and privilege changes. Provider features that depend on those operations may not work; do not remove the reviewer's existing security controls to make them run. The review profile does not make the checkout read-only.

## Define unacceptable behavior

[examples/policy.json](examples/policy.json) contains a launcher profile and a separate host policy. A rule has a unique `id`, a `kind`, an `action` (`flag` or `kill`), and an optional effective `uid`. If multiple rules match, the first matching `kill` takes precedence; otherwise the first `flag` wins.

| Kind | Matches |
| --- | --- |
| `git-push` | An explicit Git push invocation, using the kernel-reported executable and its argument vector; not the text `git push` in a prompt or shell script. |
| `exec` | An exact executable `path` and optional list of exact leading arguments (`args_prefix`, excluding argv[0]). |
| `exec-dir` | An executable under `path` with a directory boundary. For a script, Linux may report its interpreter, not the script. |
| `connect` | A host audit record for a connection attempt to the exact numeric `destination` (`IP:port`). |

Rules describe **observable behavior, not intent**. For example, to flag a newly written client connecting to a prohibited service, match the destination and reviewer's UID rather than the client's filename. That reports the connection attempt; it does **not** establish that the program performed a Git push. Aliases, renamed binaries, library calls, proxies, and encrypted traffic make command detection alone insufficient to prevent repository writes. Enforce the actual write prohibition at the remote. For stronger local restrictions, use network and filesystem isolation in addition to Smith.

## Host monitoring

See [auditd setup](deploy/audit/README.md) for dispatcher configuration, collection rules and host requirements. Adapt both the audit UID filters and Smith policy to the reviewer's real UID. Without the matching kernel audit rules, `watch` has no events to evaluate.

Start in report-only mode (`host.armed: false`). Before arming a host rule, inspect which processes it actually matches and configure `protected_exes` for critical site-specific programs. A host `kill` requires **both** an armed host and a matching `kill` rule. There is no attempt to take down unrelated clients if the subject has exited or its identity is uncertain. Monitor audit backlog/loss and dispatcher health; an empty log is not evidence of no violations. Restart the relevant process after changing its root-owned policy.

## Try it without monitoring your machine

Run the suite on native Linux (including a Linux Docker VM). The test container uses a private PID namespace, no network and no host mounts. It provisions a disposable reviewer and temporary bare Git remote. An unsupervised push first proves the remote is writable; a supervised push must leave its refs unchanged.

```sh
docker build -f tests/Dockerfile -t agent-smith-test .
docker run --rm --network none --cap-add SYS_PTRACE \
  --security-opt seccomp=unconfined agent-smith-test
```

Don't use `--privileged`, `--pid=host`, or the host's audit socket for these tests.