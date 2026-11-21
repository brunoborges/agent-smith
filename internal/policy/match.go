package policy

import (
	"path"
	"slices"
	"strings"
)

// Match returns the first matching kill, otherwise the first matching flag.
func Match(rules []Rule, o Observation) *Rule {
	var flagged *Rule
	for i := range rules {
		r := &rules[i]
		if r.UID != nil && *r.UID != o.UID {
			continue
		}
		switch r.Kind {
		case "git-push":
			if o.Kind != "exec" || !gitPush(o.Exe, o.Argv) {
				continue
			}
		case "exec":
			if o.Kind != "exec" || r.Path != o.Exe || (len(r.ArgsPrefix) > 0 &&
				(len(o.Argv) <= len(r.ArgsPrefix) || !slices.Equal(o.Argv[1:1+len(r.ArgsPrefix)], r.ArgsPrefix))) {
				continue
			}
		case "exec-dir":
			if o.Kind != "exec" || !strings.HasPrefix(o.Exe, r.Path+"/") {
				continue
			}
		case "connect":
			if o.Kind != "connect" || !o.Destination.IsValid() || o.Destination.String() != r.Destination {
				continue
			}
		default:
			continue
		}
		if r.Action == "kill" {
			return r
		}
		if flagged == nil && r.Action == "flag" {
			flagged = r
		}
	}
	return flagged
}

// Parse only the Git invocation, never reparse shell command strings.
func gitPush(exe string, argv []string) bool {
	switch path.Base(strings.TrimSuffix(exe, " (deleted)")) {
	case "git-push":
		return true
	case "git":
	default:
		return false
	}
	if len(argv) == 0 {
		return false
	}
	if path.Base(argv[0]) == "git-push" {
		return true
	}
	for i := 1; i < len(argv); i++ {
		a := argv[i]
		switch a {
		case "-h", "--help", "-v", "--version", "--exec-path", "--html-path", "--man-path", "--info-path":
			// These display information instead of dispatching a push.
			return false
		case "-C", "-c", "--git-dir", "--work-tree", "--namespace", "--super-prefix", "--shallow-file", "--config-env", "--attr-source":
			i++ // The next argument is an option value, even if it is "push".
		default:
			if !strings.HasPrefix(a, "-") {
				return a == "push"
			}
		}
	}
	return false
}
