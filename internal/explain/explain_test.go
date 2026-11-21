package explain

import (
	"bytes"
	"context"
	"errors"
	"io"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

const fixture = `{"time":"2026-11-21T00:00:00Z","source":"watch","pid":7654321,"uid":1234567,"rule":"secret-rule-canary","kind":"exec","action":"kill","outcome":"guarded","future_field":"arbitrary-secret-canary"}`

func TestProviderBoundaries(t *testing.T) {
	const credential = "synthetic-credential-not-a-real-token"
	const result = "Policy explanation.\x1b[1A\nAnother line.\u202e"
	q := strconv.Quote(result)
	// strconv.Quote produces Go escapes, not JSON escapes, for ESC.
	q = strings.ReplaceAll(q, `\x1b`, `\u001b`)
	for _, tc := range []struct{ provider, env, target, raw string }{
		{"copilot", "AGENT_SMITH_EXPLAIN_COPILOT_TOKEN", "-p", result},
		{"claude", "AGENT_SMITH_EXPLAIN_CLAUDE_KEY", "https://api.anthropic.com/v1/messages", `{"type":"message","role":"assistant","content":[{"type":"text","text":` + q + `}]}`},
		{"codex", "AGENT_SMITH_EXPLAIN_CODEX_KEY", "https://api.openai.com/v1/responses", `{"status":"completed","output":[{"type":"reasoning"},{"type":"message","role":"assistant","content":[{"type":"output_text","text":` + q + `}]}]}`},
	} {
		t.Run(tc.provider, func(t *testing.T) {
			t.Setenv("HTTP_PROXY", "proxy-canary")
			t.Setenv("HOME", "home-canary")
			t.Setenv("GH_TOKEN", "ambient-token-canary")
			var out bytes.Buffer
			err := run(tc.provider, strings.NewReader(fixture), &out, func(k string) string {
				if k != tc.env {
					t.Fatalf("unexpected credential lookup %q", k)
				}
				return credential
			}, func(ctx context.Context, req invocation) ([]byte, error) {
				deadline, ok := ctx.Deadline()
				if !ok || time.Until(deadline) > timeout {
					t.Fatal("provider not time-limited")
				}
				cmd := sandbox(ctx, req)
				argv := strings.Join(cmd.Args, " ")
				env := strings.Join(cmd.Env, " ")
				if cmd.Path != bwrap || cmd.Dir != "/" || !strings.Contains(argv, "--chdir /work") ||
					!strings.Contains(argv, "--tmpfs /home") || !strings.Contains(argv, "--ro-bind "+rootfs+" / ") {
					t.Fatal("provider not launched in a clean filesystem")
				}
				for _, s := range []string{"2026-11-21", "7654321", "1234567", "secret-rule-canary", "arbitrary-secret-canary",
					"proxy-canary", "home-canary", "ambient-token-canary"} {
					if strings.Contains(argv+env+req.stdin, s) {
						t.Fatalf("unexpected data forwarded: %s", s)
					}
				}
				if strings.Contains(argv, credential) || !slices.Contains(req.args, tc.target) {
					t.Fatal("bad target or credential in argv")
				}
				for _, label := range []string{"watch", "exec", "kill", "guarded"} {
					if !strings.Contains(argv, label) {
						t.Fatalf("missing classification %q", label)
					}
				}
				if tc.provider == "copilot" {
					if !strings.Contains(profile, "\ntools: []\n") || !slices.Contains(req.args, "--agent=smith-explain") ||
						!strings.Contains(argv, "--ro-bind-data 3 ") || req.stdin != "" || !slices.Contains(cmd.Env, "COPILOT_GITHUB_TOKEN="+credential) {
						t.Fatal("incorrect Copilot tool or auth boundary")
					}
				} else if req.binary != "curl" || req.args[0] != "--disable" || !strings.Contains(req.stdin, credential+"\n") ||
					strings.Contains(env, credential) || !slices.Contains(req.args, "@-") {
					t.Fatal("incorrect direct API auth boundary")
				}
				return []byte(tc.raw), nil
			})
			if err != nil || out.String() != "Untrusted provider explanation: "+strconv.QuoteToASCII(result)+"\n" {
				t.Fatalf("result: %q, err: %v", out.String(), err)
			}
		})
	}
}

func TestRejectBeforeLaunch(t *testing.T) {
	for _, tc := range []struct{ provider, input, key string }{
		{"unknown", fixture, "fake"},
		{"copilot", `not json`, "fake"},
		{"claude", fixture + `{}`, "fake"},
		{"claude", `null`, "fake"},
		{"claude", strings.Repeat(" ", maxEvent) + fixture, "fake"},
		{"codex", strings.Replace(fixture, `"guarded"`, `"guarded: secret"`, 1), "fake"},
		{"copilot", strings.Replace(fixture, `"exec"`, `"SECRET"`, 1), "fake"},
		{"codex", fixture, "fake\nHeader: secret"},
		{"claude", fixture, ""},
	} {
		var out bytes.Buffer
		err := run(tc.provider, strings.NewReader(tc.input), &out, func(string) string { return tc.key }, func(context.Context, invocation) ([]byte, error) {
			t.Fatal("rejected event triggered an invocation")
			return nil, nil
		})
		if err == nil || out.Len() != 0 || strings.Contains(err.Error(), "secret") {
			t.Fatalf("did not reject privately: %v", err)
		}
	}
}

func TestAdapterFailures(t *testing.T) {
	for _, tc := range []struct{ provider, raw string }{
		{"copilot", " "}, {"copilot", "fake-key"}, {"copilot", strings.Repeat("a", maxText+1)},
		{"claude", `{"type":"error","error":{"message":"private service diagnostic"}}`},
		{"codex", `{"status":"completed","output":[{"type":"function_call"}]}`},
		{"codex", `not json`}, {"claude", strings.Repeat(" ", maxResponse+1)},
	} {
		var out bytes.Buffer
		err := run(tc.provider, strings.NewReader(fixture), &out, func(string) string { return "fake-key" }, func(context.Context, invocation) ([]byte, error) {
			return []byte(tc.raw), nil
		})
		if err == nil || out.Len() != 0 || strings.Contains(err.Error(), "fake-key") || strings.Contains(err.Error(), "service diagnostic") {
			t.Fatalf("%s failure: %v", tc.provider, err)
		}
	}
	failed := errors.New("sandbox or provider failed")
	err := run("copilot", strings.NewReader(fixture), io.Discard, func(string) string { return "fake-key" }, func(context.Context, invocation) ([]byte, error) {
		return nil, failed
	})
	if !errors.Is(err, failed) {
		t.Fatal("launch failure lost")
	}
	var buf boundedBuffer
	if _, err := io.Copy(&buf, strings.NewReader(strings.Repeat("a", maxResponse+1))); err == nil || buf.buf.Len() > maxResponse {
		t.Fatal("oversized subprocess output accepted")
	}
}
