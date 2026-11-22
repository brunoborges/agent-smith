// Package explain provides an optional, post-event analyst command. No provider
// response is a policy input, and no monitor should import this package.
package explain

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/brunoborges/agent-smith/internal/policy"
)

const (
	maxEvent    = 16 << 10
	maxResponse = 64 << 10
	maxText     = 4 << 10
	timeout     = 45 * time.Second
)

// Run explains one completed event. Call only in a separate CLI invocation.
func Run(provider string, in io.Reader, out io.Writer) error {
	if err := requireAnalyst(); err != nil {
		return err
	}
	return run(provider, in, out, os.Getenv, launch)
}

type invocation struct {
	binary, stdin string
	args, env     []string
}

func run(provider string, in io.Reader, out io.Writer, getenv func(string) string, execute func(context.Context, invocation) ([]byte, error)) error {
	var key string
	switch provider {
	case "copilot":
		key = "AGENT_SMITH_EXPLAIN_COPILOT_TOKEN"
	case "claude":
		key = "AGENT_SMITH_EXPLAIN_CLAUDE_KEY"
	case "codex":
		key = "AGENT_SMITH_EXPLAIN_CODEX_KEY"
	default:
		return errors.New("explain: provider must be copilot, claude or codex")
	}
	data, err := io.ReadAll(io.LimitReader(in, maxEvent+1))
	var event policy.Event
	if err != nil || len(data) > maxEvent || !utf8.Valid(data) || json.Unmarshal(data, &event) != nil {
		return errors.New("explain: expected one bounded JSON event")
	}
	// Never serialize Event. Fields not selected here (including future fields)
	// cannot be accidentally interpolated into the prompt.
	source := allowed(event.Source, "run", "watch")
	kind := allowed(event.Kind, "git-push", "exec", "exec-dir", "connect")
	action := allowed(event.Action, "flag", "kill")
	if source == "" || kind == "" || action == "" {
		return errors.New("explain: unsupported event classification")
	}
	outcome := allowed(event.Outcome, "blocked", "flagged", "reported", "disarmed", "guarded", "stale", "signal-sent", "signal-failed")
	if outcome == "" {
		return errors.New("explain: unsupported event outcome")
	}
	prompt := "Briefly explain this local policy classification to an analyst. Distinguish the requested action from the observed outcome. Do not suggest commands.\nSource: " + source + "\nKind: " + kind + "\nRequested action: " + action + "\nObserved outcome: " + outcome
	credential := getenv(key)
	if len(credential) == 0 || len(credential) > 4096 || strings.IndexFunc(credential, func(r rune) bool { return r < '!' || r > '~' }) != -1 {
		return fmt.Errorf("explain: supply a valid analyst credential in %s", key)
	}
	cmd := request(provider, prompt, credential)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	raw, err := execute(ctx, cmd)
	if ctx.Err() != nil {
		return errors.New("explain: provider timed out")
	}
	if err != nil {
		return err
	}
	text, err := response(provider, raw)
	if err != nil {
		return err
	}
	if strings.Contains(text, credential) {
		return errors.New("explain: credential in provider response")
	}
	// A single, explicitly untrusted line. Escape terminal controls, bidi
	// overrides, embedded newlines, and non-ASCII before writing to a terminal.
	_, err = fmt.Fprintf(out, "Untrusted provider explanation: %s\n", strconv.QuoteToASCII(text))
	return err
}

func allowed(value string, labels ...string) string {
	for _, label := range labels {
		if value == label {
			return label
		}
	}
	return ""
}

func request(provider, prompt, credential string) invocation {
	if provider == "copilot" {
		return invocation{
			binary: "copilot",
			env:    []string{"COPILOT_GITHUB_TOKEN=" + credential},
			args: []string{"--agent=smith-explain", "--disable-builtin-mcps", "--disable-mcp-server=computer-use",
				"--no-custom-instructions", "--no-ask-user", "--no-bash-env", "--no-auto-update",
				"--sync-session=off", "--disable-client-telemetry", "--silent", "--no-color", "-p", prompt},
		}
	}
	var url, headers string
	var body map[string]any
	if provider == "claude" {
		url = "https://api.anthropic.com/v1/messages"
		headers = "x-api-key: " + credential + "\nanthropic-version: 2023-06-01\n"
		body = map[string]any{
			"model": "claude-haiku-4-5", "max_tokens": 256,
			"messages": []map[string]string{{"role": "user", "content": prompt}},
		}
	} else {
		url = "https://api.openai.com/v1/responses"
		headers = "Authorization: Bearer " + credential + "\n"
		body = map[string]any{
			"model": "gpt-5.3-codex", "input": prompt, "max_output_tokens": 512, "reasoning": map[string]string{"effort": "low"},
			"tools": []string{}, "tool_choice": "none", "store": false,
		}
	}
	payload, _ := json.Marshal(body) // only JSON primitives
	// No shell, curlrc, redirects, proxy, retries, key in argv, or response
	// diagnostics. The only stdin is our own validated authentication header.
	return invocation{binary: "curl", stdin: headers, args: []string{
		"--disable", "--proto", "=https", "--tlsv1.2", "--noproxy", "*", "--silent", "--fail",
		"--max-time", "40", "--max-filesize", strconv.Itoa(maxResponse), "--header", "@-",
		"--header", "Content-Type: application/json", "--data-binary", string(payload), url,
	}}
}

func response(provider string, raw []byte) (string, error) {
	invalid := errors.New("explain: missing, oversized or invalid provider response")
	if len(raw) > maxResponse || !utf8.Valid(raw) {
		return "", invalid
	}
	var text string
	switch provider {
	case "copilot":
		text = string(raw)
	case "claude":
		var msg struct {
			Type, Role string
			Content    []struct{ Type, Text string }
		}
		if json.Unmarshal(raw, &msg) != nil || msg.Type != "message" || msg.Role != "assistant" || len(msg.Content) != 1 || msg.Content[0].Type != "text" {
			return "", invalid
		}
		text = msg.Content[0].Text
	case "codex":
		var res struct {
			Status string
			Output []struct {
				Type, Role string
				Content    []struct{ Type, Text string }
			}
		}
		if json.Unmarshal(raw, &res) != nil || res.Status != "completed" {
			return "", invalid
		}
		for _, item := range res.Output {
			if item.Type == "reasoning" {
				continue
			}
			if item.Type != "message" || item.Role != "assistant" || text != "" || len(item.Content) != 1 || item.Content[0].Type != "output_text" {
				return "", invalid
			}
			text = item.Content[0].Text
		}
	}
	text = strings.TrimSpace(text)
	if text == "" || len(text) > maxText {
		return "", invalid
	}
	return text, nil
}

type boundedBuffer struct{ buf bytes.Buffer }

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if len(p) > maxResponse-b.buf.Len() {
		return 0, errors.New("explain: provider output too large")
	}
	return b.buf.Write(p)
}
