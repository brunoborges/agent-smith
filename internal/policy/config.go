package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"path"
	"regexp"
	"strings"
)

var identifier = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`)

func decode(r io.Reader) (*Config, error) {
	const limit = 1 << 20
	b, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil || len(b) > limit {
		return nil, errors.New("cannot read policy within 1 MiB limit")
	}
	var c Config
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&c); err != nil {
		return nil, fmt.Errorf("invalid policy: %w", err)
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, errors.New("unexpected data after policy")
	}
	if len(c.Profiles) == 0 && len(c.Host.Rules) == 0 {
		return nil, errors.New("policy contains no rules")
	}
	for _, p := range c.Host.ProtectedExes {
		if !absolute(p) {
			return nil, errors.New("protected_exes requires absolute executable paths")
		}
	}
	ids := make(map[string]bool)
	check := func(rules []Rule, host bool) error {
		for i := range rules {
			r := &rules[i]
			if !identifier.MatchString(r.ID) || ids[r.ID] {
				return fmt.Errorf("invalid or duplicate rule ID: %q", r.ID)
			}
			ids[r.ID] = true
			if err := r.validate(host); err != nil {
				return fmt.Errorf("rule %s: %w", r.ID, err)
			}
		}
		return nil
	}
	for name, rules := range c.Profiles {
		if !identifier.MatchString(name) || len(rules) == 0 {
			return nil, fmt.Errorf("invalid or empty profile: %q", name)
		}
		if err := check(rules, false); err != nil {
			return nil, err
		}
	}
	if err := check(c.Host.Rules, true); err != nil {
		return nil, err
	}
	return &c, nil
}

func absolute(p string) bool {
	return path.IsAbs(p) && p != "/" && path.Clean(p) == p && !strings.ContainsRune(p, 0)
}

func (r *Rule) validate(host bool) error {
	if r.Action != "flag" && r.Action != "kill" {
		return errors.New("action must be flag or kill")
	}
	if r.Kind != "exec" && len(r.ArgsPrefix) != 0 {
		return errors.New("args_prefix is only supported on exec")
	}
	if r.Kind != "connect" && r.Destination != "" {
		return errors.New("destination is only supported on connect")
	}
	switch r.Kind {
	case "exec", "exec-dir":
		if !absolute(r.Path) {
			return errors.New("path must be an absolute, clean non-root path")
		}
		return nil
	case "git-push":
	case "connect":
		if !host {
			return errors.New("connect rules require the host audit stream")
		}
		addr, err := netip.ParseAddrPort(r.Destination)
		if err != nil || addr.Port() == 0 || addr.Addr().Zone() != "" {
			return errors.New("destination must be a numeric IP:port")
		}
		r.Destination = netip.AddrPortFrom(addr.Addr().Unmap(), addr.Port()).String()
	default:
		return errors.New("kind must be git-push, exec, exec-dir or connect")
	}
	if r.Path != "" {
		return errors.New("path is only supported on exec and exec-dir")
	}
	return nil
}
