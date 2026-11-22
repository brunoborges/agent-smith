// Package policy defines the local, deterministic policy shared by both monitors.
package policy

import (
	"net/netip"
	"time"
)

type Config struct {
	Profiles map[string][]Rule `json:"profiles"`
	Host     Host              `json:"host"`
}

type Host struct {
	Armed         bool     `json:"armed"`
	ProtectedExes []string `json:"protected_exes"`
	Rules         []Rule   `json:"rules"`
}

type Rule struct {
	ID          string   `json:"id"`
	Action      string   `json:"action"` // flag or kill
	Kind        string   `json:"kind"`   // git-push, exec, exec-dir, connect
	UID         *uint32  `json:"uid,omitempty"`
	Path        string   `json:"path,omitempty"`
	ArgsPrefix  []string `json:"args_prefix,omitempty"` // excludes argv[0]
	Destination string   `json:"destination,omitempty"` // exact numeric IP:port
}

type Observation struct {
	Kind        string // exec or connect
	UID         uint32 // effective uid
	Exe         string // kernel-reported executable
	Argv        []string
	Destination netip.AddrPort
}

// Event deliberately carries no paths, prompts, credentials, command lines or URLs.
type Event struct {
	Time    time.Time `json:"time"`
	Source  string    `json:"source"` // run or watch
	PID     int       `json:"pid,omitempty"`
	UID     uint32    `json:"uid"`
	Rule    string    `json:"rule,omitempty"`
	Kind    string    `json:"kind"`
	Action  string    `json:"action"`
	Outcome string    `json:"outcome"`
}

type Emit func(Event) error
