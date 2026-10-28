package respond

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// nft identifiers/addresses are validated so nothing user-provided is ever
// interpreted as shell syntax (arguments are passed as an argv slice).
var (
	reNFTIdent = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_-]{0,30}$`)
	reNFTAddr  = regexp.MustCompile(`^[a-fA-F0-9.:/\[\]%]{1,255}$`)
	reNFTProto = regexp.MustCompile(`^(tcp|udp|udplite|sctp|dccp|icmp|icmpv6|ip|ip6)$`)
)

// NFTProvider manages an nftables table used for network response actions.
type NFTProvider struct {
	Enabled bool
	DryRun  bool
	Table   string
	Chain   string
}

func (p NFTProvider) table() string {
	if reNFTIdent.MatchString(p.Table) {
		return p.Table
	}
	return "edr"
}

func (p NFTProvider) chain() string {
	if reNFTIdent.MatchString(p.Chain) {
		return p.Chain
	}
	return "blocklist"
}

func (p NFTProvider) active() bool { return p.Enabled && !p.DryRun }

// ApplyBlock drops traffic to the request's remote address / port.
func (p NFTProvider) ApplyBlock(req Request) Result {
	table, chain := p.table(), p.chain()
	proto := strings.ToLower(req.Protocol)
	if !reNFTProto.MatchString(proto) {
		proto = "tcp"
	}
	// Build the rule with correct nft ordering: [ip|ip6 daddr X] [proto dport Y] drop.
	rule := []string{"nft", "add", "rule", "inet", table, chain}
	if req.RemoteAddr != "" {
		if !reNFTAddr.MatchString(req.RemoteAddr) {
			return Result{Action: req.Action, Success: false, Detail: "invalid remote address"}
		}
		layer := "ip"
		if strings.Contains(req.RemoteAddr, ":") {
			layer = "ip6"
		}
		rule = append(rule, layer, "daddr", req.RemoteAddr)
	}
	if req.RemotePort > 0 {
		rule = append(rule, proto, "dport", strconv.Itoa(req.RemotePort))
	}
	rule = append(rule, "drop")

	cmds := [][]string{
		{"nft", "add", "table", "inet", table},
		{"nft", "add", "chain", "inet", table, chain, "{", "type", "filter", "hook", "output", "priority", "0", ";", "policy", "accept", ";", "}"},
		rule,
	}
	if !p.active() {
		return Result{Action: req.Action, Success: true, Enforced: false, Detail: "nft dry-run: " + joinCmds(cmds)}
	}
	if err := runNFT(cmds); err != nil {
		return Result{Action: req.Action, Success: false, Detail: err.Error()}
	}
	return Result{Action: req.Action, Success: true, Enforced: true, Detail: "nft block applied"}
}

// ApplyIsolate drops all egress except loopback, established, DNS and SSH.
func (p NFTProvider) ApplyIsolate() Result {
	table := p.table()
	iso := "isolate"
	script := strings.Join([]string{
		fmt.Sprintf("add table inet %s", table),
		fmt.Sprintf("add chain inet %s %s { type filter hook output priority 0; policy drop; }", table, iso),
		fmt.Sprintf("add rule inet %s %s oifname lo accept", table, iso),
		fmt.Sprintf("add rule inet %s %s ct state established,related accept", table, iso),
		fmt.Sprintf("add rule inet %s %s tcp dport 22 accept", table, iso),
		fmt.Sprintf("add rule inet %s %s udp dport 53 accept", table, iso),
		fmt.Sprintf("add rule inet %s %s tcp dport 53 accept", table, iso),
	}, "\n") + "\n"
	if !p.active() {
		return Result{Action: "network_isolate", Success: true, Enforced: false, Detail: "nft dry-run isolate:\n" + script}
	}
	if _, err := exec.LookPath("nft"); err != nil {
		return Result{Action: "network_isolate", Success: false, Detail: "nft binary not found"}
	}
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	if out, err := cmd.CombinedOutput(); err != nil {
		return Result{Action: "network_isolate", Success: false, Detail: fmt.Sprintf("%s: %v", strings.TrimSpace(string(out)), err)}
	}
	return Result{Action: "network_isolate", Success: true, Enforced: true, Detail: "network isolation applied"}
}

// Rollback removes the edr table (restoring pre-response state).
func (p NFTProvider) Rollback() Result {
	table := p.table()
	if !p.active() {
		return Result{Action: "network_restore", Success: true, Enforced: false, Detail: "nft dry-run: delete table inet " + table}
	}
	if _, err := exec.LookPath("nft"); err != nil {
		return Result{Action: "network_restore", Success: false, Detail: "nft binary not found"}
	}
	out, err := exec.Command("nft", "delete", "table", "inet", table).CombinedOutput()
	if err != nil && !strings.Contains(string(out), "No such file") {
		return Result{Action: "network_restore", Success: false, Detail: fmt.Sprintf("%s: %v", strings.TrimSpace(string(out)), err)}
	}
	return Result{Action: "network_restore", Success: true, Enforced: true, Detail: "edr table removed"}
}

// SaveSnapshot stores the current ruleset so a response can be rolled back.
func (p NFTProvider) SaveSnapshot(path string) error {
	if !p.active() {
		return nil
	}
	if _, err := exec.LookPath("nft"); err != nil {
		return fmt.Errorf("nft binary not found")
	}
	out, err := exec.Command("nft", "list", "ruleset").CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft list ruleset: %s: %w", strings.TrimSpace(string(out)), err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, out, 0o600)
}

// RestoreSnapshot applies a saved ruleset then removes the edr table.
func (p NFTProvider) RestoreSnapshot(path string) error {
	if !p.active() {
		return nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if _, err := exec.LookPath("nft"); err != nil {
		return fmt.Errorf("nft binary not found")
	}
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = bytes.NewReader(raw)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nft restore: %s: %w", strings.TrimSpace(string(out)), err)
	}
	_ = p.Rollback()
	_ = os.Remove(path)
	return nil
}

func runNFT(cmds [][]string) error {
	if _, err := exec.LookPath("nft"); err != nil {
		return fmt.Errorf("nft binary not found")
	}
	for _, args := range cmds {
		if len(args) == 0 {
			continue
		}
		if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
			return fmt.Errorf("%s: %v", strings.TrimSpace(string(out)), err)
		}
	}
	return nil
}

func joinCmds(cmds [][]string) string {
	parts := make([]string, 0, len(cmds))
	for _, c := range cmds {
		parts = append(parts, strings.Join(c, " "))
	}
	return strings.Join(parts, " && ")
}
