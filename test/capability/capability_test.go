// Package capability exercises user-visible capabilities end to end and
// regenerates docs/capability-matrix.md. Every capability listed here must be
// backed by real code paths — no hand-written entries.
package capability

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"edr/internal/adminauth"
	"edr/internal/audit"
	"edr/internal/bpf"
	"edr/internal/capmatrix"
	"edr/internal/center"
	"edr/internal/collect"
	"edr/internal/control"
	"edr/internal/datapath"
	"edr/internal/detect"
	"edr/internal/event"
	"edr/internal/integrity"
	"edr/internal/lease"
	"edr/internal/notify"
	"edr/internal/pipeline"
	"edr/internal/policy"
	"edr/internal/protect"
	"edr/internal/requestauth"
	"edr/internal/respond"
	"edr/internal/rootkit"
	"edr/internal/supervisor"
)

func TestCapabilityMatrix(t *testing.T) {
	reg := capmatrix.New()

	add := func(name string, fn func(*testing.T) (bool, string)) {
		ok, detail := fn(t)
		reg.Check(name, ok, detail)
	}
	add("event_schema_versioned", checkEventRoundTrip)
	add("pipeline_backpressure_counted", checkBackpressure)
	add("detect_kind_indexing", checkKindIndexing)
	add("detect_rule_allow_override", checkAllowOverride)
	add("audit_chain_detects_tamper", checkChainTamper)
	add("audit_chain_rejects_downgrade", checkChainDowngrade)
	add("audit_anchor_detects_truncation", checkAnchorTruncation)
	add("policy_signature_verified", checkPolicySignature)
	add("bpf_record_contract", checkBPFRecordContract)
	add("procfs_enrich_cmdline", checkProcfsEnrich)
	add("datapath_file_rule_compile", checkDatapathCompile)
	add("datapath_frame_codec", checkDatapathFrame)
	add("bpf_record_decodes_privesc", checkBPFPrivescDecode)
	add("detect_sequence_fires", checkSequenceFires)
	add("policy_signed_reload", checkSignedReload)
	add("respond_quarantine_file", checkRespondQuarantine)
	add("respond_kill_dryrun_unenforced", checkRespondKillDryRun)
	add("respond_quarantine_restore", checkQuarantineRestore)
	add("respond_nft_arg_validation", checkNFTValidation)
	add("audit_verifyfile_detects_tamper", checkAuditVerifyFileTamper)
	add("audit_anchor_file_truncation", checkAuditAnchorTruncation)
	add("admin_token_replay_rejected", checkAdminTokenReplay)
	add("control_peercred_uid_enforced", checkPeerCredEnforced)
	add("ha_lease_prevents_split_brain", checkLease)
	add("ha_supervisor_quorum_intent", checkQuorum)
	add("center_ingest_and_query", checkCenterIngest)
	add("center_detects_chain_gap", checkCenterGap)
	add("center_correlation_cross_host", checkCenterCorrelation)
	add("center_attack_tagging", checkCenterAttackTag)
	add("center_case_lifecycle", checkCaseLifecycle)
	add("center_report_export", checkReportExport)
	add("center_action_orchestration", checkActionOrchestration)
	add("integrity_masquerade_detect", checkMasquerade)
	add("rootkit_hidden_process", checkRootkitHiddenProcess)
	add("rootkit_hidden_module", checkRootkitHiddenModule)
	add("rootkit_syscall_integrity", checkRootkitSyscallIntegrity)
	add("rootkit_hidden_connection", checkRootkitHiddenConnection)
	add("notify_webhook_dispatch_severity_filter", checkNotifyDispatch)
	add("protect_sentinel_stale_heartbeat", checkSentinelStale)
	add("protect_sentinel_pid_tamper", checkSentinelPIDTamper)
	add("protect_sentinel_binary_tamper", checkSentinelBinaryTamper)
	add("bpf_guard_event_decodes", checkBPFGuardEventDecodes)
	add("bpf_guard_attach_family_decodes", checkBPFGuardAttachFamily)
	add("lsm_availability_matches_sysfs", checkLSMAvailability)
	add("requestauth_query_and_body_signed", checkRequestAuthSigned)
	add("audit_hmac_keyed_chain", checkAuditHMAC)
	add("io_uring_vfs_fileop_decodes", checkIOUringFileOp)
	add("bpf_exec_cmdline_decodes", checkExecCmdlineDecodes)

	// Write the generated matrix at the module root.
	out := filepath.Join("..", "..", "docs", "capability-matrix.md")
	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
		t.Fatalf("mkdir docs: %v", err)
	}
	f, err := os.Create(out)
	if err != nil {
		t.Fatalf("create matrix: %v", err)
	}
	defer f.Close()
	if err := reg.Render(f); err != nil {
		t.Fatalf("render: %v", err)
	}
	if !reg.AllPassed() {
		t.Fatalf("capability matrix has failures:\n%s", renderString(reg))
	}
}

func renderString(r *capmatrix.Registry) string {
	var b strings.Builder
	_ = r.Render(&b)
	return b.String()
}

func checkEventRoundTrip(t *testing.T) (bool, string) {
	t.Helper()
	ev := &event.Event{Kind: event.KindExec, PID: 7, Comm: "bash"}
	ev.Normalize()
	if ev.SchemaVersion != event.SchemaVersion {
		return false, "schema version not stamped"
	}
	raw, err := json.Marshal(ev)
	if err != nil {
		return false, err.Error()
	}
	var back event.Event
	if err := json.Unmarshal(raw, &back); err != nil {
		return false, err.Error()
	}
	if back.Kind != event.KindExec || back.PID != 7 {
		return false, "round trip mismatch"
	}
	return true, "schema " + event.SchemaVersion
}

func checkBackpressure(t *testing.T) (bool, string) {
	t.Helper()
	p := pipeline.New("cap", 1, noopStage{})
	if !p.Submit(&event.Event{}) {
		return false, "first submit rejected unexpectedly"
	}
	if p.Submit(&event.Event{}) {
		return false, "second submit should be dropped"
	}
	if p.Stats().Dropped != 1 {
		return false, "drop not counted"
	}
	return true, "drops counted"
}

type noopStage struct{}

func (noopStage) Name() string                      { return "noop" }
func (noopStage) Handle(*event.Event) (bool, error) { return true, nil }

func checkKindIndexing(t *testing.T) (bool, string) {
	t.Helper()
	eng := mustEngine(t, policy.Rule{
		ID: "p", Category: policy.CategoryProcess, Severity: "high",
		Decision: policy.DecisionBlock, Action: policy.ActionKill,
		When: &policy.Node{Op: policy.OpEq, Field: policy.FieldProcessName, Value: "nc"},
	})
	if len(eng.Match(&event.Event{Kind: event.KindFileOp, File: &event.FileInfo{Path: "/x"}})) != 0 {
		return false, "process rule matched a file event"
	}
	if len(eng.Match(&event.Event{Kind: event.KindExec, Comm: "nc"})) != 1 {
		return false, "process rule did not match exec"
	}
	return true, "indexed by kind"
}

func checkAllowOverride(t *testing.T) (bool, string) {
	t.Helper()
	eng := mustEngine(t, policy.Rule{
		ID: "b", Category: policy.CategoryProcess, Severity: "high",
		Decision: policy.DecisionBlock, Action: policy.ActionKill,
		When:  &policy.Node{Op: policy.OpEq, Field: policy.FieldProcessName, Value: "nc"},
		Allow: &policy.Node{Op: policy.OpContains, Field: policy.FieldCmdline, Value: "trusted"},
	})
	ev := &event.Event{Kind: event.KindExec, Comm: "nc", Proc: &event.ProcInfo{Cmdline: []string{"nc", "trusted"}}}
	got := eng.Match(ev)
	if len(got) != 1 || got[0].Decision != policy.DecisionAllow {
		return false, "allow override not applied"
	}
	return true, "override applied"
}

func checkChainTamper(t *testing.T) (bool, string) {
	t.Helper()
	key := []byte("0123456789abcdef0123456789abcdef")
	c := audit.NewChain(key)
	raw := seal(t, c, 3)
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	var m map[string]any
	if err := json.Unmarshal([]byte(lines[1]), &m); err != nil {
		return false, err.Error()
	}
	m["comm"] = "tampered"
	nb, _ := json.Marshal(m)
	lines[1] = string(nb)
	res, _ := audit.Verify(bytes.NewReader([]byte(strings.Join(lines, "\n")+"\n")), key)
	if res.OK {
		return false, "tamper undetected"
	}
	return true, "hash_mismatch raised"
}

func checkChainDowngrade(t *testing.T) (bool, string) {
	t.Helper()
	key := []byte("0123456789abcdef0123456789abcdef")
	c := audit.NewChain(key)
	raw := seal(t, c, 3)
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	var m map[string]any
	if err := json.Unmarshal([]byte(lines[1]), &m); err != nil {
		return false, err.Error()
	}
	delete(m, "chain")
	nb, _ := json.Marshal(m)
	lines[1] = string(nb)
	res, _ := audit.Verify(bytes.NewReader([]byte(strings.Join(lines, "\n")+"\n")), key)
	if res.OK {
		return false, "downgrade accepted"
	}
	return true, "missing_integrity raised"
}

func checkAnchorTruncation(t *testing.T) (bool, string) {
	t.Helper()
	c := audit.NewChain(nil)
	seal(t, c, 3)
	head := c.Head()
	a := audit.NewAnchor()
	if err := a.Push(head); err != nil {
		return false, err.Error()
	}
	rolled := head
	rolled.Seq = head.Seq - 1
	if len(a.CrossVerify(rolled)) == 0 {
		return false, "truncation undetected"
	}
	return true, "truncation detected"
}

func checkPolicySignature(t *testing.T) (bool, string) {
	t.Helper()
	dir := t.TempDir()
	key, err := policy.GenerateSigningKey()
	if err != nil {
		return false, err.Error()
	}
	path := filepath.Join(dir, "p.json")
	raw, _ := json.Marshal(&policy.Policy{SchemaVersion: policy.SchemaVersion})
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		return false, err.Error()
	}
	if err := policy.SignPolicy(key, path); err != nil {
		return false, err.Error()
	}
	ok, err := policy.VerifyPolicyFile(key.Public, path)
	if err != nil || !ok {
		return false, "valid signature rejected"
	}
	if err := os.WriteFile(path, append(raw, '\n'), 0o600); err != nil {
		return false, err.Error()
	}
	if ok, _ := policy.VerifyPolicyFile(key.Public, path); ok {
		return false, "tampered policy accepted"
	}
	return true, "ed25519 verified"
}

func checkBPFRecordContract(t *testing.T) (bool, string) {
	t.Helper()
	// Documented offsets from internal/bpf (probes/common.h layout).
	raw := make([]byte, bpf.RecordSize)
	raw[32] = byte(event.KindExec)  // offType
	copy(raw[60:], "bash")          // offComm
	copy(raw[76:], "/usr/bin/bash") // offFilename
	ev, ok := bpf.DecodeRecord(raw)
	if !ok {
		return false, "decode rejected canonical record"
	}
	if ev.Kind != event.KindExec || ev.Comm != "bash" || ev.Proc == nil || ev.Proc.Exe != "/usr/bin/bash" {
		return false, "decoded fields mismatch"
	}
	if _, ok := bpf.DecodeRecord(make([]byte, 8)); ok {
		return false, "short record accepted"
	}
	return true, "record contract stable"
}

func checkProcfsEnrich(t *testing.T) (bool, string) {
	t.Helper()
	ev := &event.Event{Kind: event.KindExec, PID: uint32(os.Getpid())}
	collect.Enrich(ev, collect.Fields{Cmdline: true})
	if ev.Proc == nil || len(ev.Proc.Cmdline) == 0 {
		return false, "cmdline not enriched"
	}
	if ev.Proc.StartTicks == 0 {
		return false, "process identity (start ticks) missing"
	}
	return true, "cmdline + identity enriched"
}

func checkBPFPrivescDecode(t *testing.T) (bool, string) {
	t.Helper()
	raw := make([]byte, bpf.RecordSize)
	raw[32] = byte(event.KindPrivesc)          // offType
	binary.LittleEndian.PutUint32(raw[24:], 1) // offReserved = setuid
	ev, ok := bpf.DecodeRecord(raw)
	if !ok {
		return false, "decode failed"
	}
	if ev.Detail["privtype"] != "setuid" {
		return false, "privtype not decoded"
	}
	return true, "privesc decoded"
}

type capFakeReader struct {
	hb  uint64
	pid uint32
}

func (f *capFakeReader) ReadHeartbeat() (uint64, error) { return f.hb, nil }
func (f *capFakeReader) ReadAgentPID() (uint32, error)  { return f.pid, nil }

func checkSentinelStale(t *testing.T) (bool, string) {
	t.Helper()
	r := &capFakeReader{hb: 1, pid: 7}
	s := protect.NewSentinel(protect.Config{Reader: r, AgentPID: 7})
	if ok, _ := s.Check(); !ok {
		return false, "first check failed"
	}
	if ok, _ := s.Check(); ok {
		return false, "stale heartbeat not detected"
	}
	return true, "stale heartbeat detected"
}

func checkSentinelPIDTamper(t *testing.T) (bool, string) {
	t.Helper()
	r := &capFakeReader{hb: 1, pid: 999}
	s := protect.NewSentinel(protect.Config{Reader: r, AgentPID: 7})
	if ok, _ := s.Check(); ok {
		return false, "agent_pid tamper not detected"
	}
	return true, "agent_pid tamper detected"
}

func checkSentinelBinaryTamper(t *testing.T) (bool, string) {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "edr-agent")
	if err := os.WriteFile(bin, []byte("original"), 0o755); err != nil {
		return false, err.Error()
	}
	r := &capFakeReader{hb: 1, pid: 7}
	s := protect.NewSentinel(protect.Config{Reader: r, AgentPID: 7, BinaryPath: bin})
	if ok, why := s.Check(); !ok {
		return false, "untampered binary failed: " + why
	}
	if err := os.WriteFile(bin, []byte("replaced-with-different-content"), 0o755); err != nil {
		return false, err.Error()
	}
	r.hb = 2
	if ok, _ := s.Check(); ok {
		return false, "binary tamper not detected"
	}
	return true, "binary tamper detected"
}

func checkRootkitHiddenProcess(t *testing.T) (bool, string) {
	t.Helper()
	proc := t.TempDir()
	tr := rootkit.NewTrackerWithClock(func() time.Time { return time.Now().Add(-time.Hour) })
	tr.Learn(&event.Event{Kind: event.KindExec, PID: 55555})
	d := rootkit.NewDetector(rootkit.Config{ProcRoot: proc, SysRoot: proc}, tr)
	for _, e := range d.RunOnce() {
		if e.Detail["rootkit_type"] == "hidden_process" && e.PID == 55555 {
			return true, "hidden process detected"
		}
	}
	return false, "hidden process not detected"
}

func checkRootkitHiddenModule(t *testing.T) (bool, string) {
	t.Helper()
	proc := t.TempDir()
	sys := t.TempDir()
	if err := os.WriteFile(filepath.Join(proc, "modules"), nil, 0o644); err != nil {
		return false, err.Error()
	}
	mod := filepath.Join(sys, "module", "evil")
	if err := os.MkdirAll(mod, 0o755); err != nil {
		return false, err.Error()
	}
	if err := os.WriteFile(filepath.Join(mod, "refcnt"), []byte("1\n"), 0o644); err != nil {
		return false, err.Error()
	}
	d := rootkit.NewDetector(rootkit.Config{ProcRoot: proc, SysRoot: sys}, rootkit.NewTracker())
	for _, e := range d.RunOnce() {
		if e.Detail["rootkit_type"] == "hidden_module" && e.Detail["module"] == "evil" {
			return true, "hidden module detected"
		}
	}
	return false, "hidden module not detected"
}

func checkRootkitSyscallIntegrity(t *testing.T) (bool, string) {
	t.Helper()
	proc := t.TempDir()
	ks := "0000000000001000 T _text\n" +
		"0000000000001500 T __x64_sys_kill\n" +
		"0000000000009000 T __x64_sys_bpf\n" +
		"0000000000002000 T _etext\n"
	if err := os.WriteFile(filepath.Join(proc, "kallsyms"), []byte(ks), 0o644); err != nil {
		return false, err.Error()
	}
	d := rootkit.NewDetector(rootkit.Config{ProcRoot: proc, SysRoot: proc}, rootkit.NewTracker())
	for _, e := range d.RunOnce() {
		if e.Detail["rootkit_type"] == "syscall_hook" {
			return true, "syscall hook detected"
		}
	}
	return false, "syscall hook not detected"
}

func checkRootkitHiddenConnection(t *testing.T) (bool, string) {
	t.Helper()
	proc := t.TempDir()
	if err := os.MkdirAll(filepath.Join(proc, "net"), 0o755); err != nil {
		return false, err.Error()
	}
	if err := os.WriteFile(filepath.Join(proc, "net", "tcp"), []byte("  sl  local_address rem_address st\n"), 0o644); err != nil {
		return false, err.Error()
	}
	tr := rootkit.NewTracker()
	tr.Learn(&event.Event{Kind: event.KindConnect, Net: &event.NetInfo{RemoteAddr: "203.0.113.7"}})
	d := rootkit.NewDetector(rootkit.Config{ProcRoot: proc, SysRoot: proc, Connections: true, Grace: time.Hour}, tr)
	for _, e := range d.RunOnce() {
		if e.Detail["rootkit_type"] == "hidden_connection" {
			return true, "hidden connection detected"
		}
	}
	return false, "hidden connection not detected"
}

func checkBPFGuardAttachFamily(t *testing.T) (bool, string) {
	t.Helper()
	// The bpf_guard also covers the attach/relink family: BPF_PROG_ATTACH=8,
	// BPF_LINK_CREATE=28, BPF_LINK_UPDATE=29. Verify the telemetry contract for
	// each command decodes cleanly.
	for _, cmd := range []uint32{8, 28, 29} {
		raw := make([]byte, bpf.RecordSize)
		raw[32] = byte(event.KindSelfProtect)        // offType
		binary.LittleEndian.PutUint32(raw[24:], cmd) // offReserved = bpf cmd
		copy(raw[76:], "bpf_object_guard")           // offFilename
		ev, ok := bpf.DecodeRecord(raw)
		if !ok || ev.Detail["syscall"] != "bpf_object_guard" || ev.Detail["detail"] != cmd {
			return false, "guard event decode failed for a cmd"
		}
	}
	return true, "attach/relink family guarded"
}

func checkExecCmdlineDecodes(t *testing.T) (bool, string) {
	t.Helper()
	raw := make([]byte, bpf.RecordSize)
	raw[32] = byte(event.KindExec)           // offType
	copy(raw[76:], "/usr/bin/bash")          // offFilename -> Exe
	copy(raw[332:], "bash\x00-c\x00echo hi") // offCmdline -> joined argv
	ev, ok := bpf.DecodeRecord(raw)
	if !ok || ev.Proc == nil || strings.Join(ev.Proc.Cmdline, " ") != "bash -c echo hi" {
		return false, "exec cmdline decode failed"
	}
	return true, "in-kernel argv decoded"
}

func checkIOUringFileOp(t *testing.T) (bool, string) {
	t.Helper()
	want := map[uint32]string{4: "vfs_unlink", 5: "vfs_rename", 6: "vfs_rename_to"}
	for op, name := range want {
		raw := make([]byte, bpf.RecordSize)
		raw[32] = byte(event.KindFileOp)            // offType
		binary.LittleEndian.PutUint32(raw[28:], op) // offFileOp
		copy(raw[76:], "secret")                    // offFilename
		ev, ok := bpf.DecodeRecord(raw)
		if !ok || ev.File == nil || ev.File.Op != name {
			return false, "vfs file-op decode failed for " + name
		}
	}
	return true, "io_uring VFS file ops decode"
}

func checkAuditHMAC(t *testing.T) (bool, string) {
	t.Helper()
	key := []byte("0123456789abcdef0123456789abcdef")
	ch := audit.NewChain(key)
	line, err := ch.Seal(&event.Event{Kind: event.KindExec, PID: 7})
	if err != nil {
		return false, err.Error()
	}
	if res, _ := audit.Verify(bytes.NewReader(line), key); !res.OK {
		return false, "valid keyed chain rejected"
	}
	if res, _ := audit.Verify(bytes.NewReader(line), []byte("ffffffffffffffffffffffffffffffff")); res.OK {
		return false, "wrong key accepted"
	}
	return true, "keyed chain verified; wrong key rejected"
}

func checkRequestAuthSigned(t *testing.T) (bool, string) {
	t.Helper()
	a := requestauth.New([]byte("secret"), 30*time.Second)
	req := httptest.NewRequest(http.MethodGet, "/v0/center/agent/actions?host=a", nil)
	a.Sign(req, nil, "r1", time.Now().UTC())
	if err := a.Authorize(req, nil); err != nil {
		return false, "valid request rejected"
	}
	req.URL.RawQuery = "host=b"
	req.Header.Set(requestauth.HeaderRequestID, "r2")
	if err := a.Authorize(req, nil); err == nil {
		return false, "query mutation accepted"
	}
	body := []byte(`[{"id":"x","action":"kill"}]`)
	sig := a.SignBody(body)
	if err := a.VerifyBody(body, sig); err != nil {
		return false, "valid body rejected"
	}
	if err := a.VerifyBody([]byte(`[{"id":"x","action":"kill","pid":9}]`), sig); err == nil {
		return false, "tampered body accepted"
	}
	return true, "query + response body signed"
}

func checkLSMAvailability(t *testing.T) (bool, string) {
	t.Helper()
	raw, _ := os.ReadFile("/sys/kernel/security/lsm")
	want := false
	for _, f := range strings.Split(strings.TrimSpace(string(raw)), ",") {
		if strings.TrimSpace(f) == "bpf" {
			want = true
		}
	}
	got := bpf.LSMAvailable()
	if got != want {
		return false, "LSMAvailable disagrees with /sys/kernel/security/lsm"
	}
	if got {
		return true, "bpf LSM present"
	}
	return true, "bpf LSM absent (kprobe path only)"
}

func checkBPFGuardEventDecodes(t *testing.T) (bool, string) {
	t.Helper()
	raw := make([]byte, bpf.RecordSize)
	raw[32] = byte(event.KindSelfProtect)         // offType
	binary.LittleEndian.PutUint32(raw[16:], 1234) // offPPID = targeted own object id
	binary.LittleEndian.PutUint32(raw[24:], 2)    // offReserved = BPF_MAP_UPDATE_ELEM
	binary.LittleEndian.PutUint32(raw[28:], 2)    // offFileOp = EDR_OWN_MAP
	copy(raw[76:], "bpf_object_guard")            // offFilename
	ev, ok := bpf.DecodeRecord(raw)
	if !ok {
		return false, "decode failed"
	}
	if ev.Detail["syscall"] != "bpf_object_guard" {
		return false, "guard event syscall not decoded"
	}
	if ev.Detail["detail"] != uint32(2) {
		return false, "guard cmd not decoded"
	}
	if ev.Detail["target_pid"] != uint32(1234) {
		return false, "guard target object id not decoded"
	}
	return true, "bpf guard event decoded"
}

func checkActionOrchestration(t *testing.T) (bool, string) {
	t.Helper()
	s, err := center.OpenActions(t.TempDir())
	if err != nil {
		return false, err.Error()
	}
	if _, err := s.Create("h", "rm -rf /", 0, "", "", 0, "", "op"); err == nil {
		return false, "arbitrary command was accepted"
	}
	a, err := s.Create("h", "kill", 123, "", "", 0, "t", "op")
	if err != nil {
		return false, err.Error()
	}
	if err := s.Approve(a.ID, "approver"); err != nil {
		return false, err.Error()
	}
	pend := s.PendingFor("h")
	if len(pend) != 1 || pend[0].State != "dispatched" {
		return false, "approved action not dispatched"
	}
	if err := s.Complete(a.ID, true, true, "killed"); err != nil {
		return false, err.Error()
	}
	final, _ := s.Get(a.ID)
	if final.State != "completed" {
		return false, "result not recorded"
	}
	return true, "closed-enum + approval + result"
}

func checkNotifyDispatch(t *testing.T) (bool, string) {
	t.Helper()
	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		w.WriteHeader(200)
	}))
	defer srv.Close()
	d := notify.New(notify.Config{Webhooks: []notify.WebhookConfig{{URL: srv.URL, Format: "generic", MinSeverity: "high"}}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d.Start(ctx)
	low := &event.Event{Host: "h", Detail: map[string]any{"severity": "low", "matched_rules": []string{"r"}}}
	high := &event.Event{Host: "h", Detail: map[string]any{"severity": "high", "matched_rules": []string{"r"}}}
	d.Notify(low)
	d.Notify(high)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && atomic.LoadInt64(&hits) == 0 {
		time.Sleep(5 * time.Millisecond)
	}
	if atomic.LoadInt64(&hits) != 1 {
		return false, "expected exactly 1 delivery after severity filter"
	}
	return true, "webhook delivered, low severity filtered"
}

func checkMasquerade(t *testing.T) (bool, string) {
	t.Helper()
	procs := []integrity.Proc{
		{PID: 10, Comm: "kworker/0:1", PPID: 2},
		{PID: 20, Comm: "kworker/0:2", PPID: 1, Exe: "/tmp/fake"},
		{PID: 30, Comm: "bash", PPID: 1, Exe: "/usr/bin/bash"},
	}
	fs := integrity.Detect(procs)
	if len(fs) != 1 || fs[0].PID != 20 {
		return false, "masquerade detection wrong"
	}
	return true, "kworker forgery detected"
}

func checkReportExport(t *testing.T) (bool, string) {
	t.Helper()
	evs := []event.Event{{Host: "h", Time: time.Now(), Kind: event.KindExec, Comm: "bash",
		Detail: map[string]any{"matched_rules": []string{"T1059-x"}, "severity": "high"}}}
	cef := center.ExportCEF(evs)
	if len(cef) != 1 || !strings.HasPrefix(cef[0], "CEF:0|") {
		return false, "cef export malformed"
	}
	leef := center.ExportLEEF(evs)
	if len(leef) != 1 || !strings.HasPrefix(leef[0], "LEEF:2.0|") {
		return false, "leef export malformed"
	}
	return true, "CEF + LEEF export"
}

func checkCaseLifecycle(t *testing.T) (bool, string) {
	t.Helper()
	s, err := center.OpenCases(t.TempDir())
	if err != nil {
		return false, err.Error()
	}
	c, err := s.Create("test", "high", []string{"h"}, []string{"r"}, []string{"T1059"})
	if err != nil {
		return false, err.Error()
	}
	if err := s.SetStatus(c.ID, "investigating"); err != nil {
		return false, err.Error()
	}
	if err := s.SetDisposition(c.ID, "true_positive", "ok"); err != nil {
		return false, err.Error()
	}
	g, ok := s.Get(c.ID)
	if !ok || g.Status != "investigating" || g.Disposition != "true_positive" {
		return false, "case state not applied"
	}
	return true, "case lifecycle ok"
}

func checkCenterCorrelation(t *testing.T) (bool, string) {
	t.Helper()
	now := time.Now()
	mk := func(host, remote string) event.Event {
		return event.Event{Host: host, Time: now, Net: &event.NetInfo{RemoteAddr: remote},
			Detail: map[string]any{"matched_rules": []string{"T1071-c2"}, "severity": "high"}}
	}
	fs := center.Correlate([]event.Event{mk("a", "1.2.3.4"), mk("b", "1.2.3.4")}, time.Minute)
	for _, f := range fs {
		if f.Kind == "cross_host_indicator" && len(f.Hosts) == 2 {
			return true, "cross-host indicator correlated"
		}
	}
	return false, "no cross-host finding"
}

func checkCenterAttackTag(t *testing.T) (bool, string) {
	t.Helper()
	if a := center.Tag("T1059-001-shell"); a.Tactic != "execution" {
		return false, "tag mismatch for T1059"
	}
	if a := center.Tag("random-rule"); a.Tactic != "unknown" {
		return false, "unknown rule not mapped to unknown"
	}
	return true, "ATT&CK tagging works"
}

func checkCenterIngest(t *testing.T) (bool, string) {
	t.Helper()
	s, err := center.Open(t.TempDir())
	if err != nil {
		return false, err.Error()
	}
	now := time.Now()
	mk := func(seq uint64, prev, hash string) event.Event {
		return event.Event{Host: "h", Time: now, Chain: &event.ChainMeta{Version: "v2.0", ChainID: "c", Seq: seq, PrevHash: prev, Hash: hash}}
	}
	s.Ingest(mk(1, "", "a"))
	s.Ingest(mk(2, "a", "b"))
	out, err := s.Query(center.Filter{Host: "h", Limit: 10})
	if err != nil || len(out) != 2 {
		return false, "aggregated query mismatch"
	}
	return true, "ingested and queried"
}

func checkCenterGap(t *testing.T) (bool, string) {
	t.Helper()
	s, err := center.Open(t.TempDir())
	if err != nil {
		return false, err.Error()
	}
	now := time.Now()
	mk := func(seq uint64, prev, hash string) event.Event {
		return event.Event{Host: "h", Time: now, Chain: &event.ChainMeta{Version: "v2.0", ChainID: "c", Seq: seq, PrevHash: prev, Hash: hash}}
	}
	s.Ingest(mk(1, "", "a"))
	s.Ingest(mk(4, "a", "d"))
	hs := s.Hosts()
	if len(hs) != 1 || hs[0].Gaps != 1 {
		return false, "chain gap not recorded"
	}
	return true, "gap detected"
}

func checkLease(t *testing.T) (bool, string) {
	t.Helper()
	dir := t.TempDir()
	now := time.Now()
	if _, err := lease.Acquire(dir, "peer", "A", 10*time.Second, now); err != nil {
		return false, err.Error()
	}
	if _, err := lease.Acquire(dir, "peer", "B", 10*time.Second, now); err != lease.ErrHeld {
		return false, "second holder was not rejected"
	}
	return true, "single-writer lease enforced"
}

func checkQuorum(t *testing.T) (bool, string) {
	t.Helper()
	secret := []byte("s3cr3t")
	srv := supervisor.NewServer(supervisor.Options{Secret: secret, DecisionTTL: time.Minute, HostStaleAfter: time.Second})
	body, _ := json.Marshal(supervisor.HeartbeatRequest{
		RequestID: "r", SentAt: time.Now().UTC(),
		InstanceID: "edr-a", PeerInstanceID: "edr-b", PeerState: "down",
	})
	r := httptest.NewRequest("POST", "/v0/supervisor/heartbeat", bytes.NewReader(body))
	requestauth.New(secret, time.Minute).Sign(r, body, "r", time.Now().UTC())
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		return false, "supervisor rejected signed heartbeat"
	}
	var out supervisor.HeartbeatResponse
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		return false, err.Error()
	}
	if out.RestartIntent == nil {
		return false, "no restart intent issued"
	}
	return true, "quorum issued restart intent"
}

func checkAdminTokenReplay(t *testing.T) (bool, string) {
	t.Helper()
	key, err := adminauth.GenerateKey()
	if err != nil {
		return false, err.Error()
	}
	a := adminauth.New(key)
	tok, _, err := a.Issue("shutdown", time.Now())
	if err != nil {
		return false, err.Error()
	}
	if err := a.Verify(tok, "shutdown", time.Now()); err != nil {
		return false, "valid token rejected"
	}
	if err := a.Verify(tok, "shutdown", time.Now()); err == nil {
		return false, "replay accepted"
	}
	return true, "replay rejected"
}

func checkPeerCredEnforced(t *testing.T) (bool, string) {
	t.Helper()
	h := control.New(control.Deps{AllowedUIDs: []int{0}}).Handler()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/v0/status", nil))
	if w.Code != http.StatusForbidden {
		return false, "request without peer credentials was not rejected"
	}
	return true, "uid allow-list enforced"
}

func checkAuditVerifyFileTamper(t *testing.T) (bool, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	key := []byte("0123456789abcdef0123456789abcdef")
	c := audit.NewChain(key)
	var lines [][]byte
	for i := 0; i < 3; i++ {
		l, err := c.Seal(&event.Event{Kind: event.KindExec, PID: uint32(i + 1)})
		if err != nil {
			return false, err.Error()
		}
		lines = append(lines, l)
	}
	var m map[string]any
	if err := json.Unmarshal(lines[1], &m); err != nil {
		return false, err.Error()
	}
	m["comm"] = "tampered"
	nb, _ := json.Marshal(m)
	lines[1] = append(nb, '\n')
	var buf bytes.Buffer
	for _, l := range lines {
		buf.Write(l)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		return false, err.Error()
	}
	res, err := audit.VerifyFile(path, key)
	if err != nil {
		return false, err.Error()
	}
	if res.OK {
		return false, "tamper undetected"
	}
	return true, "tamper detected"
}

func checkAuditAnchorTruncation(t *testing.T) (bool, string) {
	t.Helper()
	dir := t.TempDir()
	an := audit.NewAnchorWithOptions(audit.AnchorOptions{FilePath: filepath.Join(dir, "anchor.json")})
	if err := an.Push(audit.Head{ChainID: "c1", Seq: 10, Hash: "hash10"}); err != nil {
		return false, err.Error()
	}
	issues := an.CrossVerify(audit.Head{ChainID: "c1", Seq: 7, Hash: "hash7"})
	if len(issues) == 0 {
		return false, "truncation undetected"
	}
	return true, "truncation detected"
}

func checkQuarantineRestore(t *testing.T) (bool, string) {
	t.Helper()
	dir := t.TempDir()
	orig := filepath.Join(dir, "x")
	if err := os.WriteFile(orig, []byte("p"), 0o600); err != nil {
		return false, err.Error()
	}
	l := &respond.Local{DryRun: false, QuarantineDir: filepath.Join(dir, "q")}
	if r := l.Apply(respond.Request{Action: respond.ActionQuarantine, Path: orig}); !r.Success {
		return false, "quarantine failed"
	}
	if _, err := os.Stat(orig); !os.IsNotExist(err) {
		return false, "file not moved"
	}
	if r := l.RestoreQuarantine(orig); !r.Success {
		return false, "restore failed"
	}
	if _, err := os.Stat(orig); err != nil {
		return false, "file not restored"
	}
	return true, "quarantine round-trip"
}

func checkNFTValidation(t *testing.T) (bool, string) {
	t.Helper()
	p := respond.NFTProvider{DryRun: true}
	if r := p.ApplyBlock(respond.Request{Action: respond.ActionNFTBlock, RemoteAddr: "1.2.3.4; reboot"}); r.Success {
		return false, "injection address accepted"
	}
	if r := p.ApplyBlock(respond.Request{Action: respond.ActionNFTBlock, RemoteAddr: "10.0.0.1"}); !r.Success || r.Enforced {
		return false, "valid dry-run block wrong"
	}
	return true, "nft args validated, dry-run unenforced"
}

func checkRespondQuarantine(t *testing.T) (bool, string) {
	t.Helper()
	dir := t.TempDir()
	target := filepath.Join(dir, "suspect")
	if err := os.WriteFile(target, []byte("p"), 0o600); err != nil {
		return false, err.Error()
	}
	l := &respond.Local{DryRun: false, QuarantineDir: filepath.Join(dir, "q")}
	res := l.Apply(respond.Request{Action: respond.ActionQuarantine, Path: target})
	if !res.Success || !res.Enforced {
		return false, "quarantine not enforced"
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		return false, "file not moved"
	}
	return true, "file quarantined"
}

func checkRespondKillDryRun(t *testing.T) (bool, string) {
	t.Helper()
	l := &respond.Local{DryRun: true}
	res := l.Apply(respond.Request{Action: respond.ActionKill, PID: 4242})
	if !res.Success || res.Enforced {
		return false, "dry-run semantics wrong"
	}
	return true, "unenforced by default"
}

func checkSequenceFires(t *testing.T) (bool, string) {
	t.Helper()
	p := &policy.Policy{
		SchemaVersion: policy.SchemaVersion,
		Sequences: []policy.SequenceRule{{
			ID: "S", Category: policy.CategoryProcess, Severity: "high",
			Decision: policy.DecisionAlert, Action: policy.ActionLog,
			WithinSec: 60, SamePID: true,
			Stages: []policy.Node{
				{Op: policy.OpEq, Field: policy.FieldProcessName, Value: "curl"},
				{Op: policy.OpEq, Field: policy.FieldProcessName, Value: "bash"},
			},
		}},
	}
	if err := p.Validate(); err != nil {
		return false, err.Error()
	}
	eng := detect.New(p)
	seq := detect.NewSequenceEngine()
	seq.Observe(eng, p, &event.Event{Kind: event.KindExec, PID: 7, Comm: "curl"})
	got := seq.Observe(eng, p, &event.Event{Kind: event.KindExec, PID: 7, Comm: "bash"})
	if len(got) != 1 {
		return false, "sequence did not fire"
	}
	return true, "sequence completed"
}

func checkSignedReload(t *testing.T) (bool, string) {
	t.Helper()
	dir := t.TempDir()
	key, err := policy.GenerateSigningKey()
	if err != nil {
		return false, err.Error()
	}
	path := filepath.Join(dir, "p.json")
	raw, _ := json.Marshal(&policy.Policy{SchemaVersion: policy.SchemaVersion})
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		return false, err.Error()
	}
	if err := policy.SignPolicy(key, path); err != nil {
		return false, err.Error()
	}
	if _, err := policy.LoadSigned(path, key.Public); err != nil {
		return false, "signed load failed"
	}
	if err := os.WriteFile(path, append(raw, ' '), 0o600); err != nil {
		return false, err.Error()
	}
	if _, err := policy.LoadSigned(path, key.Public); err == nil {
		return false, "tampered policy accepted"
	}
	return true, "signed reload verified"
}

func checkDatapathCompile(t *testing.T) (bool, string) {
	t.Helper()
	p := &policy.Policy{SchemaVersion: policy.SchemaVersion, Rules: []policy.Rule{{
		ID: "D", Category: policy.CategoryFile, Severity: "high",
		Decision: policy.DecisionBlock, Action: policy.ActionFanotifyDeny,
		When: &policy.Node{Op: policy.OpStartsWith, Field: policy.FieldFilePath, Value: "/tmp/watch/"},
	}}}
	if err := p.Validate(); err != nil {
		return false, err.Error()
	}
	rules := datapath.CompileFileRules(p)
	if len(rules) != 1 || rules[0].PathPrefix != "/tmp/watch/" {
		return false, "file rule not compiled"
	}
	return true, "1 file deny rule compiled"
}

func checkDatapathFrame(t *testing.T) (bool, string) {
	t.Helper()
	frame, err := datapath.EncodeFrame(datapath.Message{
		Type: "policy", Version: 1,
		Rules: []datapath.FileRule{{ID: "r", PathPrefix: "/x/", Decision: "block"}},
	})
	if err != nil {
		return false, err.Error()
	}
	m, err := datapath.DecodeFrame(frame[4:])
	if err != nil {
		return false, err.Error()
	}
	if m.Type != "policy" || m.Version != 1 || len(m.Rules) != 1 {
		return false, "round trip mismatch"
	}
	return true, "frame codec stable"
}

func mustEngine(t *testing.T, rules ...policy.Rule) *detect.Engine {
	t.Helper()
	p := &policy.Policy{SchemaVersion: policy.SchemaVersion, Rules: rules}
	if err := p.Validate(); err != nil {
		t.Fatalf("invalid policy: %v", err)
	}
	return detect.New(p)
}

func seal(t *testing.T, c *audit.Chain, n int) []byte {
	t.Helper()
	var buf bytes.Buffer
	for i := 0; i < n; i++ {
		line, err := c.Seal(&event.Event{Kind: event.KindExec, PID: uint32(i + 1), Comm: "p"})
		if err != nil {
			t.Fatalf("seal: %v", err)
		}
		buf.Write(line)
	}
	return buf.Bytes()
}
