package explain

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"
)

const (
	bwrap   = "/usr/bin/bwrap"
	rootfs  = "/opt/agent-smith/explain-root"
	profile = "---\nname: smith-explain\ndescription: Explain local policy event classifications.\ntools: []\n---\nRespond to the given classification only. You have no tools.\n"
)

// Only host sources are the administrator's immutable, credential-free
// runtime image and the resolver configuration. Never bind / or $PWD.
func sandbox(ctx context.Context, call invocation) *exec.Cmd {
	args := []string{
		"--unshare-all", "--unshare-user", "--disable-userns", "--share-net", "--die-with-parent", "--new-session", "--cap-drop", "ALL",
		"--ro-bind", rootfs, "/", "--ro-bind", "/etc/resolv.conf", "/etc/resolv.conf", "--proc", "/proc", "--dev", "/dev",
		"--size", "33554432", "--tmpfs", "/tmp", "--size", "33554432", "--tmpfs", "/home", "--dir", "/home/analyst",
		"--size", "1048576", "--tmpfs", "/work", "--chdir", "/work",
	}
	if call.binary == "copilot" {
		args = append(args, "--dir", "/home/analyst/.copilot/agents", "--ro-bind-data", "3", "/home/analyst/.copilot/agents/smith-explain.agent.md")
	}
	args = append(args, "--", "/usr/bin/"+call.binary)
	cmd := exec.CommandContext(ctx, bwrap, append(args, call.args...)...)
	cmd.Dir = "/"
	cmd.Env = append([]string{"PATH=/usr/bin:/bin", "HOME=/home/analyst", "USER=agent-smith-analyst",
		"LC_ALL=C", "TMPDIR=/tmp", "COPILOT_HOME=/home/analyst/.copilot", "XDG_CONFIG_HOME=/home/analyst/.config",
		"XDG_CACHE_HOME=/home/analyst/.cache", "XDG_DATA_HOME=/home/analyst/.local/share"}, call.env...)
	cmd.Stdin = strings.NewReader(call.stdin)
	cmd.WaitDelay = time.Second
	return cmd
}

func launch(ctx context.Context, call invocation) ([]byte, error) {
	cmd := sandbox(ctx, call)
	if call.binary == "copilot" {
		// Supply the tiny fixed profile as FD 3, never as a workspace file.
		r, w, err := os.Pipe()
		if err != nil {
			return nil, errors.New("explain: cannot stage private agent profile")
		}
		defer r.Close()
		_, err = io.WriteString(w, profile)
		closeErr := w.Close()
		if err != nil || closeErr != nil {
			return nil, errors.New("explain: cannot stage private agent profile")
		}
		cmd.ExtraFiles = []*os.File{r}
	}
	var stdout boundedBuffer
	cmd.Stdout = &stdout
	// Stderr deliberately goes to /dev/null. Diagnostics can contain secrets.
	if err := cmd.Run(); err != nil {
		return nil, errors.New("explain: sandbox or provider failed (check setup, credentials and service availability)")
	}
	return stdout.buf.Bytes(), nil
}
