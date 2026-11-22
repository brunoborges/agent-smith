package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/brunoborges/agent-smith/internal/explain"
	"github.com/brunoborges/agent-smith/internal/policy"
	"github.com/brunoborges/agent-smith/internal/supervisor"
	"github.com/brunoborges/agent-smith/internal/watch"
	"golang.org/x/sys/unix"
)

const usage = `Usage:
  agent-smith run [--policy PATH] --profile NAME --user USER --provider copilot|claude|codex [-- ARGS...]
  agent-smith run [--policy PATH] --profile NAME --user USER -- /absolute/executable [ARGS...]
  agent-smith watch [--policy PATH]                         # auditd dispatcher
  agent-smith explain --provider copilot|claude|codex       # one event on stdin, non-root

Default policy: /etc/agent-smith/policy.json
Local event log: /var/log/agent-smith.jsonl`

func main() {
	code, err := command(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "agent-smith:", err)
	}
	os.Exit(code)
}

func command(args []string) (int, error) {
	if len(args) == 0 {
		return 2, errors.New(usage)
	}
	command := args[0]
	switch command {
	case "help", "-h", "--help":
		fmt.Println(usage)
		return 0, nil
	case "run", "watch", "explain":
	default:
		return 2, errors.New(usage)
	}
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	var filename, profile, username, provider string
	if command != "explain" {
		fs.StringVar(&filename, "policy", "/etc/agent-smith/policy.json", "absolute root-owned policy path")
	}
	if command != "watch" {
		fs.StringVar(&provider, "provider", "", "copilot, claude or codex")
	}
	if command == "run" {
		fs.StringVar(&username, "user", "", "dedicated unprivileged workload account")
		fs.StringVar(&profile, "profile", "", "required workload profile")
	}
	if err := fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0, nil
		}
		return 2, err
	}
	if command != "run" && fs.NArg() != 0 {
		return 2, errors.New("unexpected positional arguments")
	}
	if command == "explain" {
		if err := explain.Run(provider, os.Stdin, os.Stdout); err != nil {
			return 1, err
		}
		return 0, nil
	}
	if os.Geteuid() != 0 {
		return 1, errors.New("run and watch require root on a dedicated Linux host")
	}
	cfg, err := policy.Load(filename)
	if err != nil {
		return 1, err
	}
	var argv []string
	if command == "run" {
		if username == "" || len(cfg.Profiles[profile]) == 0 {
			return 2, errors.New("run requires --user and a configured --profile")
		}
		argv, err = workloadCommand(provider, fs.Args())
		if err != nil {
			return 2, err
		}
	} else if len(cfg.Host.Rules) == 0 {
		return 2, errors.New("watch requires host.rules")
	}
	f, err := eventLog()
	if err != nil {
		return 1, err
	}
	defer f.Close()
	encoder := json.NewEncoder(f)
	emit := func(e policy.Event) error {
		if e.Time.IsZero() {
			e.Time = time.Now().UTC()
		}
		return encoder.Encode(e)
	}
	if command == "run" {
		code, err := supervisor.Run(username, argv, cfg.Profiles[profile], emit)
		if err != nil {
			return 1, err
		}
		return code, nil
	}
	if err := watch.Run(os.Stdin, cfg.Host, emit); err != nil {
		return 1, err
	}
	return 0, nil
}

func workloadCommand(provider string, args []string) ([]string, error) {
	switch provider {
	case "":
		if len(args) == 0 || !filepath.IsAbs(args[0]) {
			return nil, errors.New("select a provider or pass an absolute executable after --")
		}
		return args, nil
	case "copilot", "claude", "codex":
		for _, dir := range []string{"/usr/local/bin", "/usr/bin", "/bin"} {
			p := filepath.Join(dir, provider)
			if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() && st.Mode().Perm()&0111 != 0 {
				return append([]string{p}, args...), nil
			}
		}
		return nil, fmt.Errorf("%s not installed in system bin directories; pass its absolute path after --", provider)
	default:
		return nil, fmt.Errorf("unknown provider %q", provider)
	}
}

func eventLog() (*os.File, error) {
	// Fixed path beneath the system log directory, never relative to the workload.
	const path = "/var/log/agent-smith.jsonl"
	fd, err := unix.Open(path, unix.O_WRONLY|unix.O_APPEND|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0600)
	if err != nil {
		return nil, fmt.Errorf("open event log: %w", err)
	}
	f := os.NewFile(uintptr(fd), path)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Uid != 0 || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0077 != 0 || st.Nlink != 1 {
		f.Close()
		return nil, errors.New("event log must be a private regular file owned by root with one link")
	}
	return f, nil
}
