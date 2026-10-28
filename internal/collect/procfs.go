// Package collect provides host-side collection helpers: /proc enrichment
// and the pipeline stage that applies it.
package collect

import (
	"os"
	"strconv"
	"strings"

	"edr/internal/event"
)

// Fields selects which enrichment dimensions to read from /proc. Reading is
// opt-in so the pipeline only pays for what the active rules actually need
// (the "minimal enrichment" principle).
type Fields struct {
	Cmdline    bool
	Environ    bool
	MapsLibs   bool
	CapEff     bool
	Namespaces bool
	Container  bool
	ParentName bool
}

const (
	maxEnvironBytes = 64 << 10
	maxMapsBytes    = 256 << 10
	maxMapsLibs     = 512
)

// Enrich fills ev.Proc (and ev.Detail["parent_name"]) from /proc/<pid>.
// It is best-effort: a process that has exited, or a permission failure,
// simply leaves the corresponding field empty. StartTicks and Exe are always
// captured because they double as process-identity for later response actions.
func Enrich(ev *event.Event, f Fields) {
	if ev == nil || ev.PID == 0 {
		return
	}
	if ev.Proc == nil {
		ev.Proc = &event.ProcInfo{}
	}
	dir := "/proc/" + strconv.FormatUint(uint64(ev.PID), 10)

	if t, ok := startTicks(dir); ok {
		ev.Proc.StartTicks = t
	}
	if ev.Proc.Exe == "" {
		ev.Proc.Exe = readlink(dir + "/exe")
	}
	if f.Cmdline && len(ev.Proc.Cmdline) == 0 {
		// The exec probe captures argv in-kernel, which is authoritative and
		// race-free. Only fall back to /proc when it is absent: a fast-exiting
		// (or mid-exec) process can yield a partial cmdline that must not
		// overwrite the captured value.
		ev.Proc.Cmdline = cmdline(dir)
	}
	if f.Environ {
		ev.Proc.Environ = environ(dir)
	}
	if f.MapsLibs {
		ev.Proc.MapsLibs = mapsLibs(dir)
	}
	if f.CapEff {
		ev.Proc.CapEff = capEff(dir)
	}
	if f.Container {
		ev.Proc.ContainerID = containerID(dir)
	}
	if f.Namespaces {
		ev.Proc.Namespaces = namespaces(dir)
	}
	if f.ParentName {
		if name := parentName(dir); name != "" {
			if ev.Detail == nil {
				ev.Detail = map[string]any{}
			}
			ev.Detail["parent_name"] = name
		}
	}
}

func readFile(path string, limit int) []byte {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	buf := make([]byte, limit)
	n, _ := f.Read(buf)
	if n <= 0 {
		return nil
	}
	return buf[:n]
}

func readlink(path string) string {
	target, err := os.Readlink(path)
	if err != nil {
		return ""
	}
	return target
}

// splitNUL splits a NUL-separated proc file, dropping the trailing empty entry.
func splitNUL(b []byte) []string {
	if len(b) == 0 {
		return nil
	}
	parts := strings.Split(string(b), "\x00")
	if len(parts) > 0 && parts[len(parts)-1] == "" {
		parts = parts[:len(parts)-1]
	}
	return parts
}

func cmdline(dir string) []string {
	b := readFile(dir+"/cmdline", 64<<10)
	if len(b) == 0 {
		// Kernel threads have an empty cmdline; fall back to comm.
		if comm := readFile(dir+"/comm", 64); len(comm) > 0 {
			return []string{strings.TrimSpace(string(comm))}
		}
		return nil
	}
	return splitNUL(b)
}

func environ(dir string) []string {
	b := readFile(dir+"/environ", maxEnvironBytes)
	return splitNUL(b)
}

func mapsLibs(dir string) []string {
	b := readFile(dir+"/maps", maxMapsBytes)
	if len(b) == 0 {
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		if !strings.Contains(line, ".so") {
			continue
		}
		// Keep the path component (last field) to bound memory.
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		out = append(out, fields[len(fields)-1])
		if len(out) >= maxMapsLibs {
			break
		}
	}
	return out
}

func capEff(dir string) uint64 {
	for _, line := range statusLines(dir) {
		if strings.HasPrefix(line, "CapEff:") {
			v := strings.TrimSpace(strings.TrimPrefix(line, "CapEff:"))
			n, _ := strconv.ParseUint(v, 16, 64)
			return n
		}
	}
	return 0
}

func statusLines(dir string) []string {
	b := readFile(dir+"/status", 64<<10)
	if len(b) == 0 {
		return nil
	}
	return strings.Split(string(b), "\n")
}

// containerID extracts a container identifier from /proc/<pid>/cgroup.
// Handles docker/containerd (bare id) and cgroup v2 kubepods paths.
func containerID(dir string) string {
	b := readFile(dir+"/cgroup", 16<<10)
	if len(b) == 0 {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		if !(strings.Contains(line, "docker") || strings.Contains(line, "containerd") ||
			strings.Contains(line, "kubepods") || strings.Contains(line, "crio")) {
			continue
		}
		parts := strings.Split(strings.TrimSpace(line), "/")
		id := parts[len(parts)-1]
		id = strings.TrimSuffix(id, ".scope")
		if len(id) >= 12 {
			return id
		}
	}
	return ""
}

// namespaces reads /proc/<pid>/ns/* and parses the inode from each link.
func namespaces(dir string) *event.NamespaceIDs {
	ids := event.NamespaceIDs{
		PID:   nsInode(dir + "/ns/pid"),
		Mount: nsInode(dir + "/ns/mnt"),
		Net:   nsInode(dir + "/ns/net"),
		User:  nsInode(dir + "/ns/user"),
		UTS:   nsInode(dir + "/ns/uts"),
		IPC:   nsInode(dir + "/ns/ipc"),
	}
	if ids == (event.NamespaceIDs{}) {
		return nil
	}
	return &ids
}

func nsInode(path string) uint64 {
	// Link target looks like "pid:[4026531836]".
	target := readlink(path)
	open := strings.IndexByte(target, '[')
	closeIdx := strings.IndexByte(target, ']')
	if open < 0 || closeIdx <= open {
		return 0
	}
	n, _ := strconv.ParseUint(target[open+1:closeIdx], 10, 64)
	return n
}

// startTicks parses field 22 (starttime) from /proc/<pid>/stat.
func startTicks(dir string) (uint64, bool) {
	b := readFile(dir+"/stat", 8<<10)
	if len(b) == 0 {
		return 0, false
	}
	s := string(b)
	closeParen := strings.LastIndexByte(s, ')')
	if closeParen < 0 || closeParen+2 >= len(s) {
		return 0, false
	}
	fields := strings.Fields(s[closeParen+2:])
	// fields[0] is state (field 3); starttime is field 22 -> index 19.
	const idx = 19
	if idx >= len(fields) {
		return 0, false
	}
	v, err := strconv.ParseUint(fields[idx], 10, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

func parentName(dir string) string {
	b := readFile(dir+"/stat", 8<<10)
	if len(b) == 0 {
		return ""
	}
	s := string(b)
	closeParen := strings.LastIndexByte(s, ')')
	if closeParen < 0 || closeParen+2 >= len(s) {
		return ""
	}
	fields := strings.Fields(s[closeParen+2:])
	if len(fields) < 2 {
		return ""
	}
	ppid, err := strconv.Atoi(fields[1])
	if err != nil || ppid <= 0 {
		return ""
	}
	comm, _ := os.ReadFile("/proc/" + strconv.Itoa(ppid) + "/comm")
	return strings.TrimSpace(string(comm))
}
