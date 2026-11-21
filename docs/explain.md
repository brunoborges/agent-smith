# Optional analyst explanations (Linux)

`agent-smith explain --provider copilot|claude|codex` reads **one JSON event followed by EOF** and makes an external inference request. It is a separate command, not a callback: neither `run` nor `watch` needs a provider, token, network access, or any setup below. Do **not** invoke `explain` from auditd, a supervisor, a privileged service, `sudo -E`, or the account being monitored.

## One-time setup

1. Give a human analyst a separate local login named `agent-smith-analyst`, with its own non-root primary group, **no other groups**, no sudo privileges, no file capabilities and no access to workload credentials or workspaces. Keep the host executable and runtime under administrator control. The command verifies the analyst's identity and refuses elevated or mixed credentials and unexpected inherited descriptors. It does not accept a username or drop root.
2. Install **non-setuid, capability-free `/usr/bin/bwrap`** on the host. Use a Linux host that permits this account to create unprivileged user namespaces. Its bubblewrap must support `--unshare-user`, `--disable-userns`, `--ro-bind-data`, `--size` and `--die-with-parent`. If isolation fails, the command fails; do not substitute a privileged launcher.
3. Install a clean, administrator-maintained runtime filesystem at **`/opt/agent-smith/explain-root`**. It is *not the host's `/`*. Do not copy a workstation home, an existing logged-in container, `/run` sockets, API keys, machine credentials, hooks, MCP configs, extensions, projects, or nested mounts into it. No component may be modifiable by the analyst or workloads. It needs CA certificates, TLS and DNS support, `/usr/bin/curl` (Claude/Codex) and/or the official native `/usr/bin/copilot` and its runtime dependencies. `/etc/resolv.conf` must be a regular mount target. Provide an `/etc/passwd` entry for the analyst's numeric UID if required by your Copilot build.

   For example, on Debian an administrator can **build a fresh runtime**, not run an explanation, with:

   ```sh
   install -d -m 0755 /opt/agent-smith
   debootstrap --variant=minbase --include=ca-certificates,curl bookworm \
     /opt/agent-smith/explain-root https://deb.debian.org/debian
   install -d -m 0755 /opt/agent-smith/explain-root/work
   ```

   For Copilot, also install a verified release of the native CLI in the runtime at the path above. Pin your tested version. Its `--help` must support the options in `internal/explain/explain.go`; it must implement [agent profiles with `tools: []`](https://docs.github.com/en/copilot/reference/custom-agents-configuration#tools). Do not use a shell wrapper or login helper. Keep the image and its trust store patched. Use an outbound firewall/allowlist if the analyst host requires one; the provider needs network access.

## Credentials and transport

Set **only the credential for the selected provider**, in the analyst's login session using a secret manager or other non-logging mechanism. Do not pass it on the command line. The command never consults `gh auth`, provider login caches, workstation tokens, or environment-selected endpoints. A provider's access controls, billing and retention policies still apply.

| `--provider` | Analyst-supplied variable | Backend |
|---|---|---|
| `copilot` | `AGENT_SMITH_EXPLAIN_COPILOT_TOKEN` | A fine-grained GitHub PAT with **Copilot Requests** only; no repo permissions. [Copilot CLI](https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-command-reference) uses a fresh fixed profile with `tools: []`, disabled built-in MCPs and `computer-use`, no custom instructions and no session sync. |
| `claude` | `AGENT_SMITH_EXPLAIN_CLAUDE_KEY` | A separate, budget-limited Anthropic workspace key. Stateless HTTPS [`POST /v1/messages`](https://platform.claude.com/docs/en/api/messages), `claude-haiku-4-5`, no tools. Not a Claude Code subscription login. |
| `codex` | `AGENT_SMITH_EXPLAIN_CODEX_KEY` | A restricted OpenAI project key with permission to create Responses. HTTPS [`POST /v1/responses`](https://developers.openai.com/api/reference/resources/responses/methods/create), `gpt-5.3-codex`, no tools, `store: false`. Not a ChatGPT subscription login. |

There is no GitHub Models or cross-provider fallback. The documented [Claude CLI `--bare`](https://code.claude.com/docs/en/cli-reference) still enables built-in tools by itself; [Codex read-only sandboxing](https://developers.openai.com/codex/security/) does not forbid reading. The direct APIs avoid both coding-agent runtimes altogether. HTTPS uses the runtime's CA roots, no proxy, no redirects or retries, and auth headers on a private pipe.

## Use

Have an authorized operator export **one** event into a file the analyst may read. Do not grant the analyst unrestricted access to a privileged log. Then, **from the analyst's own login**:

```sh
agent-smith explain --provider codex < one-event.json
```

Every invocation gets a fresh `/work`, `/tmp`, home and configuration, a read-only runtime, private PID namespace, and a fixed environment. No host workspace, user home, inherited provider config, shell startup scripts or local agent tools are supplied. The only event values that may enter a prompt are fixed labels for `source`, `kind`, `action` and `outcome`; unknown classifications (including audit-health events) fail locally. Rule IDs, timestamps, UIDs, PIDs, command lines, paths, destinations, secrets and extra fields are not sent. These labels may themselves be sensitive.

Input is limited to 16 KiB; the provider has 45 seconds, a 64 KiB response ceiling and a 4 KiB explanation ceiling. On failure no explanation is emitted. Successful text is quoted and labeled **untrusted**: read it as commentary, not proof of an event, instructions to execute, or a policy decision. Re-run only if you intend another external request.
