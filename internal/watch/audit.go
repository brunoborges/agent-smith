// Package watch observes local auditd string-dispatcher events.
package watch

import (
	"encoding/binary"
	"encoding/hex"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/brunoborges/agent-smith/internal/policy"
)

const (
	execKey = "agent_smith_exec"
	connKey = "agent_smith_connect"
	maxArgs = 128
)

type recordID struct {
	ms     int64
	serial uint64
}

// Only accept the local, raw, single-node framing. Never search for a nested
// type= or msg= inside a user-controlled AUDIT_USER_* message.
func header(s string) (typ string, id recordID, body string, ok bool) {
	s, ok = strings.CutPrefix(s, "type=")
	if !ok {
		return
	}
	typ, s, ok = strings.Cut(s, " msg=audit(")
	if !ok || len(typ) == 0 || len(typ) > 48 || strings.ContainsAny(typ, " \t\"'") {
		return "", id, "", false
	}
	stamp, body, ok := strings.Cut(s, "):")
	if !ok {
		return "", id, "", false
	}
	t, serial, ok := strings.Cut(stamp, ":")
	sec, frac, dot := strings.Cut(t, ".")
	if !dot || !ok || len(sec) > 11 || len(frac) != 3 {
		return "", id, "", false
	}
	seconds, e1 := strconv.ParseUint(sec, 10, 40)
	millis, e2 := strconv.ParseUint(frac, 10, 16)
	num, e3 := strconv.ParseUint(serial, 10, 64)
	return typ, recordID{int64(seconds*1000 + millis), num}, strings.TrimSpace(body), e1 == nil && e2 == nil && e3 == nil
}

// Keep quote delimiters for raw audit's quoted-text vs unquoted-hex convention.
func fields(s string) (map[string]string, bool) {
	f := make(map[string]string)
	for len(s) > 0 {
		k, rest, ok := strings.Cut(s, "=")
		if !ok || len(k) == 0 || len(k) > 48 || len(rest) == 0 || len(f) >= 192 || strings.ContainsAny(k, " \t\"'") {
			return nil, false
		}
		var v string
		if rest[0] == '"' {
			i := strings.IndexByte(rest[1:], '"')
			if i < 0 {
				return nil, false
			}
			v, rest = rest[:i+2], rest[i+2:]
			if len(rest) > 0 && rest[0] != ' ' {
				return nil, false
			}
		} else {
			v, rest, _ = strings.Cut(rest, " ")
		}
		if _, duplicate := f[k]; duplicate || v == "" {
			return nil, false
		}
		f[k] = v
		s = strings.TrimLeft(rest, " ")
	}
	return f, true
}

func text(v string) (string, bool) {
	if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
		return v[1 : len(v)-1], true
	}
	b, err := hex.DecodeString(v)
	return string(b), len(v) != 0 && err == nil && !strings.ContainsRune(string(b), 0)
}

type fileID struct {
	major, minor, inode uint64
}

type group struct {
	first   time.Time
	bytes   int
	records int
	bad     bool
	sys     map[string]string
	args    map[int]string
	argc    int
	counted bool
	addr    string
	paths   map[int]fileID
}

func (g *group) add(typ, body string) {
	g.bytes += len(body)
	g.records++
	if g.bad || g.bytes > 32*1024 || g.records > 64 {
		g.bad = true
		return
	}
	f, ok := fields(body)
	if !ok {
		g.bad = true
		return
	}
	switch typ {
	case "SYSCALL":
		g.bad = g.sys != nil
		g.sys = f
	case "EXECVE":
		if g.args == nil {
			g.args = make(map[int]string)
		}
		for k, v := range f {
			if k == "argc" {
				n, err := strconv.ParseUint(v, 10, 16)
				g.bad = g.bad || g.counted || err != nil || n > maxArgs
				g.argc, g.counted = int(n), true
				continue
			}
			if !strings.HasPrefix(k, "a") {
				g.bad = true
				continue
			}
			i, err := strconv.ParseUint(k[1:], 10, 16)
			arg, ok := text(v)
			_, duplicate := g.args[int(i)]
			if err != nil || i >= maxArgs || !ok || duplicate {
				// Includes chunked aN_len/aN[M]. Do not match a partial prefix.
				g.bad = true
				continue
			}
			g.args[int(i)] = arg
		}
	case "SOCKADDR":
		g.bad = g.addr != "" || f["saddr"] == ""
		g.addr = f["saddr"]
	case "PATH":
		i, e1 := strconv.ParseUint(f["item"], 10, 8)
		maj, min, colon := strings.Cut(f["dev"], ":")
		major, e2 := strconv.ParseUint(maj, 16, 32)
		minor, e3 := strconv.ParseUint(min, 16, 32)
		inode, e4 := strconv.ParseUint(f["inode"], 10, 64)
		if g.paths == nil {
			g.paths = make(map[int]fileID)
		}
		_, dup := g.paths[int(i)]
		g.bad = !colon || dup || e1 != nil || e2 != nil || e3 != nil || e4 != nil
		g.paths[int(i)] = fileID{major, minor, inode}
	}
}

type evidence struct {
	policy.Observation
	pid, ppid int
	when      time.Time
	credsOK   bool
	paths     map[int]fileID
}

func syscallKind(arch, nr string) string {
	switch arch + ":" + nr {
	case "c000003e:59", "c000003e:322", "c00000b7:221", "c00000b7:281":
		return "exec"
	case "c000003e:42", "c00000b7:203":
		return "connect"
	}
	return ""
}

func destination(raw string) (netip.AddrPort, bool) {
	b, err := hex.DecodeString(raw)
	if err != nil || len(b) < 4 {
		return netip.AddrPort{}, false
	}
	var ip netip.Addr
	// The supported audit architectures are little endian. Port is network order.
	switch {
	case binary.LittleEndian.Uint16(b) == 2 && len(b) == 16:
		ip = netip.AddrFrom4([4]byte(b[4:8]))
	case binary.LittleEndian.Uint16(b) == 10 && len(b) == 28 && binary.LittleEndian.Uint32(b[24:]) == 0:
		ip = netip.AddrFrom16([16]byte(b[8:24])).Unmap()
	default:
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(ip, binary.BigEndian.Uint16(b[2:])), true
}

// The disposition is empty for unscoped/uninteresting events and "observed"
// only for complete observations. A missing field never implies UID/PID zero.
func (g *group) observe(id recordID) (e evidence, disposition string) {
	s := g.sys
	if g.bad || s == nil {
		return e, "incomplete"
	}
	key, _ := text(s["key"])
	if key != execKey && key != connKey {
		return e, ""
	}
	e.Kind = syscallKind(s["arch"], s["syscall"])
	if (key == execKey && e.Kind != "exec") || (key == connKey && e.Kind != "connect") {
		return e, "unsupported"
	}
	// A connect observation is a destination *attempt*, including EINPROGRESS
	// and failed connects. For exec we need a successful image transition.
	if e.Kind == "exec" && s["success"] == "no" {
		return e, ""
	}
	if s["success"] != "yes" && s["success"] != "no" {
		return e, "incomplete"
	}
	pid, e1 := strconv.ParseUint(s["pid"], 10, 31)
	ppid, e2 := strconv.ParseUint(s["ppid"], 10, 31)
	uid, e3 := strconv.ParseUint(s["euid"], 10, 32)
	exe, ok := text(s["exe"])
	items, e4 := strconv.ParseUint(s["items"], 10, 8)
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || pid == 0 || !ok || !filepath.IsAbs(exe) ||
		filepath.Clean(exe) != exe || int(items) != len(g.paths) {
		return e, "incomplete"
	}
	for i := 0; i < int(items); i++ {
		if _, ok := g.paths[i]; !ok {
			return e, "incomplete"
		}
	}
	e.Exe, e.UID = exe, uint32(uid)
	e.when, e.pid, e.ppid, e.paths = time.UnixMilli(id.ms), int(pid), int(ppid), g.paths
	e.credsOK = true
	for _, field := range []string{"uid", "suid", "fsuid", "auid"} {
		e.credsOK = e.credsOK && s[field] == s["euid"]
	}
	if e.Kind == "exec" {
		if !g.counted || g.addr != "" || len(g.args) != g.argc || len(g.paths) == 0 {
			return e, "incomplete"
		}
		for i := 0; i < g.argc; i++ {
			arg, ok := g.args[i]
			if !ok {
				return e, "incomplete"
			}
			e.Argv = append(e.Argv, arg)
		}
	} else {
		if g.args != nil || g.addr == "" {
			return e, "incomplete"
		}
		if e.Destination, ok = destination(g.addr); !ok {
			// Unix-domain/other socket families aren't numeric IP rules.
			return e, "unsupported"
		}
	}
	return e, "observed"
}
