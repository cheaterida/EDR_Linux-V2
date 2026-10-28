// Command edrctl is the operator CLI: offline policy/audit tooling plus a
// client for the agent's control-plane Unix-socket API.
package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"edr/internal/adminauth"
	"edr/internal/audit"
	"edr/internal/policy"
	"edr/internal/requestauth"
)

var version = "v2.0.0-m8"

const defaultSocket = "/run/edr/agent.sock"

func main() {
	args := os.Args[1:]
	socket := defaultSocket
	var rest []string
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--socket":
			if i+1 < len(args) {
				socket = args[i+1]
				i++
			}
		case strings.HasPrefix(args[i], "--socket="):
			socket = strings.TrimPrefix(args[i], "--socket=")
		default:
			rest = append(rest, args[i])
		}
	}
	if len(rest) == 0 {
		usage()
		os.Exit(2)
	}
	var err error
	switch rest[0] {
	case "version":
		fmt.Println("edrctl", version)
	case "status", "health", "metrics":
		err = apiGet(socket, "/v0/"+rest[0])
	case "events":
		err = eventsCmd(socket, rest[1:])
	case "policy":
		err = policyCmd(socket, rest[1:])
	case "admin":
		err = adminCmd(rest[1:])
	case "quarantine":
		err = quarantineCmd(socket, rest[1:])
	case "nft":
		err = nftCmd(socket, rest[1:])
	case "shutdown":
		token, _ := flagOrFile(rest[1:], "--token", "--token-file")
		err = apiPost(socket, "/v0/shutdown", token)
	case "response":
		err = responseCmd(socket, rest[1:])
	case "center":
		err = centerCmd(rest[1:])
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "edrctl:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `edrctl — Linux EDR control CLI

usage:
  edrctl [--socket PATH] status | health | metrics
  edrctl [--socket PATH] events query [--limit N] [--rule R] [--min-severity S] [--format summary]
  edrctl events verify <event.jsonl> [--key-hex H] [--key-file F] [--anchor-file A]
  edrctl events verify <event.jsonl> [--anchor-url U --secret-file F]
  edrctl [--socket PATH] policy show
  edrctl [--socket PATH] policy reload [--token T]
  edrctl policy validate <policy.json>
  edrctl policy verify <policy.json> <public.key>
  edrctl policy keygen <private.key> <public.key>
  edrctl policy sign <private.key> <policy.json>
  edrctl admin token <action> --key-file F
  edrctl [--socket PATH] quarantine list | restore <path> [--token T]
  edrctl [--socket PATH] nft rollback [--token T]
  edrctl [--socket PATH] shutdown [--token T]
  edrctl [--socket PATH] response <action> [--pid P] [--path P] [--addr A] [--port N] [--token T]
  edrctl center hosts --url http://HOST:PORT --secret S
  edrctl center events --url http://HOST:PORT --secret S [--host H] [--rule R] [--limit N]
  edrctl center correlations --url http://HOST:PORT --secret S [--limit N]
  edrctl center cases list|show <id>|create --title T [--severity S]|status <id> <st>|disposition <id> <d>
  edrctl center report --url http://HOST:PORT --secret S
  edrctl center export --url http://HOST:PORT --secret S --format cef|leef [--limit N]
  edrctl center actions list|show <id>|create --host H --action A [--pid P]|approve <id>|reject <id>`)
}

// ---- control-plane client ----

func apiClient(socket string) *http.Client {
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", socket)
			},
		},
	}
}

func apiGet(socket, path string) error {
	resp, err := apiClient(socket).Get("http://unix" + path)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	fmt.Println(strings.TrimRight(string(body), "\n"))
	return nil
}

func apiPost(socket, path, token string) error {
	req, err := http.NewRequest(http.MethodPost, "http://unix"+path, nil)
	if err != nil {
		return err
	}
	if token != "" {
		req.Header.Set("X-EDR-Admin-Token", token)
	}
	return doAPI(apiClient(socket), req)
}

func apiPostJSON(socket, path, token string, body any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, "http://unix"+path, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("X-EDR-Admin-Token", token)
	}
	return doAPI(apiClient(socket), req)
}

func doAPI(client *http.Client, req *http.Request) error {
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	fmt.Println(strings.TrimRight(string(body), "\n"))
	return nil
}

func quarantineCmd(socket string, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: edrctl quarantine list | restore <path> [--token T]")
	}
	switch args[0] {
	case "list":
		return apiGet(socket, "/v0/quarantine/list")
	case "restore":
		if len(args) < 2 {
			return fmt.Errorf("path required")
		}
		token, _ := flagOrFile(args[2:], "--token", "--token-file")
		return apiPostJSON(socket, "/v0/quarantine/restore", token, map[string]any{"path": args[1]})
	default:
		return fmt.Errorf("unknown quarantine subcommand %q", args[0])
	}
}

func nftCmd(socket string, args []string) error {
	if len(args) < 1 || args[0] != "rollback" {
		return fmt.Errorf("usage: edrctl nft rollback [--token T]")
	}
	token, _ := flagOrFile(args[1:], "--token", "--token-file")
	return apiPost(socket, "/v0/response/nft/rollback", token)
}

func responseCmd(socket string, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: edrctl response <action> [--pid P] [--path P] [--addr A] [--port N] [--token T]")
	}
	action := args[0]
	token, rest := flagOrFile(args[1:], "--token", "--token-file")
	pid, rest := flagValue(rest, "--pid")
	path, rest := flagValue(rest, "--path")
	addr, rest := flagValue(rest, "--addr")
	port, rest := flagValue(rest, "--port")
	_ = rest
	body := map[string]any{"action": action}
	if pid != "" {
		if n, err := strconv.Atoi(pid); err == nil {
			body["pid"] = n
		}
	}
	if path != "" {
		body["path"] = path
	}
	if addr != "" {
		body["remote_addr"] = addr
	}
	if port != "" {
		if n, err := strconv.Atoi(port); err == nil {
			body["remote_port"] = n
		}
	}
	return apiPostJSON(socket, "/v0/response/execute", token, body)
}

// ---- flags helper ----

func flagValue(args []string, name string) (string, []string) {
	var rest []string
	val := ""
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == name:
			if i+1 < len(args) {
				val = args[i+1]
				i++
			}
		case strings.HasPrefix(args[i], name+"="):
			val = strings.TrimPrefix(args[i], name+"=")
		default:
			rest = append(rest, args[i])
		}
	}
	return val, rest
}

// flagOrFile reads a value from an inline flag, or, if absent, from a file
// named by a companion flag. Secrets passed inline are visible in
// /proc/<pid>/cmdline to other local users, so the file form is preferred.
func flagOrFile(args []string, inlineFlag, fileFlag string) (string, []string) {
	v, rest := flagValue(args, inlineFlag)
	if v != "" {
		return v, rest
	}
	f, rest := flagValue(rest, fileFlag)
	if f == "" {
		return "", rest
	}
	raw, err := os.ReadFile(f)
	if err != nil {
		return "", rest
	}
	return strings.TrimSpace(string(raw)), rest
}

// ---- events ----

func eventsCmd(socket string, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: edrctl events query|verify ...")
	}
	if args[0] == "verify" {
		return eventsVerify(args[1:])
	}
	if args[0] != "query" {
		return fmt.Errorf("unknown events subcommand %q", args[0])
	}
	limit, args := flagValue(args[1:], "--limit")
	rule, args := flagValue(args, "--rule")
	minSev, args := flagValue(args, "--min-severity")
	format, _ := flagValue(args, "--format")
	q := "?"
	if limit != "" {
		q += "limit=" + limit + "&"
	}
	if rule != "" {
		q += "rule_id=" + rule + "&"
	}
	if minSev != "" {
		q += "min_severity=" + minSev + "&"
	}
	if format != "" {
		q += "format=" + format + "&"
	}
	return apiGet(socket, "/v0/events"+strings.TrimRight(q, "&?"))
}

func eventsVerify(args []string) error {
	keyHex, args := flagValue(args, "--key-hex")
	keyFile, args := flagValue(args, "--key-file")
	anchorFile, args := flagValue(args, "--anchor-file")
	anchorURL, args := flagValue(args, "--anchor-url")
	secretFile, args := flagValue(args, "--secret-file")
	if len(args) < 1 {
		return fmt.Errorf("event path required")
	}
	path := args[0]
	var key []byte
	if keyHex != "" {
		b, err := hex.DecodeString(strings.TrimSpace(keyHex))
		if err != nil {
			return fmt.Errorf("key-hex: %w", err)
		}
		key = b
	} else if keyFile != "" {
		raw, err := os.ReadFile(keyFile)
		if err != nil {
			return err
		}
		b, err := hex.DecodeString(strings.TrimSpace(string(raw)))
		if err != nil {
			return fmt.Errorf("key-file: %w", err)
		}
		key = b
	}
	res, err := audit.VerifyFile(path, key)
	if err != nil {
		return err
	}
	fmt.Printf("ok=%v lines=%d last_seq=%d chain_id=%s\n", res.OK, res.Lines, res.LastSeq, res.ChainID)
	for _, iss := range res.Issues {
		fmt.Printf("  issue line=%d seq=%d %s: %s\n", iss.Line, iss.Seq, iss.Kind, iss.Detail)
	}
	anchorFailed := false
	if anchorFile != "" || anchorURL != "" {
		var secret []byte
		if secretFile != "" {
			raw, rerr := os.ReadFile(secretFile)
			if rerr != nil {
				return fmt.Errorf("secret-file: %w", rerr)
			}
			secret = []byte(strings.TrimSpace(string(raw)))
		}
		an := audit.NewAnchorWithOptions(audit.AnchorOptions{URL: anchorURL, FilePath: anchorFile, Secret: secret})
		if _, ok, aerr := an.FetchStrict(); aerr != nil {
			// A corrupt/unreadable anchor must not be reported as consistent.
			fmt.Printf("  anchor issue: unreadable: %v\n", aerr)
			anchorFailed = true
		} else if !ok {
			fmt.Printf("  anchor issue: missing (cross-verification skipped)\n")
			anchorFailed = true
		} else {
			local := audit.Head{ChainID: res.ChainID, Seq: res.LastSeq, Hash: res.LastHash}
			issues := an.CrossVerify(local)
			if len(issues) == 0 {
				fmt.Println("anchor: consistent")
			}
			for _, iss := range issues {
				fmt.Printf("  anchor issue: %s (expected=%s actual=%s)\n", iss.Kind, iss.Expected, iss.Actual)
				anchorFailed = true
			}
		}
	}
	if !res.OK || anchorFailed {
		return fmt.Errorf("chain verification failed")
	}
	return nil
}

// ---- policy ----

func policyCmd(socket string, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: edrctl policy validate|verify|keygen|sign|show|reload")
	}
	switch args[0] {
	case "validate":
		if len(args) < 2 {
			return fmt.Errorf("path required")
		}
		if _, err := policy.LoadFile(args[1]); err != nil {
			return err
		}
		fmt.Println("policy OK:", args[1])
		return nil
	case "verify":
		if len(args) < 3 {
			return fmt.Errorf("usage: edrctl policy verify <policy> <pubkey>")
		}
		pub, err := policy.LoadPublicKey(args[2])
		if err != nil {
			return err
		}
		ok, err := policy.VerifyPolicyFile(pub, args[1])
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("signature does not match")
		}
		fmt.Println("signature OK")
		return nil
	case "keygen":
		if len(args) < 3 {
			return fmt.Errorf("usage: edrctl policy keygen <private> <public>")
		}
		key, err := policy.GenerateSigningKey()
		if err != nil {
			return err
		}
		if err := policy.SaveSigningKey(key, args[1]); err != nil {
			return err
		}
		if err := policy.SavePublicKey(key.Public, args[2]); err != nil {
			return err
		}
		fmt.Printf("wrote %s and %s\n", args[1], args[2])
		return nil
	case "sign":
		if len(args) < 3 {
			return fmt.Errorf("usage: edrctl policy sign <private> <policy>")
		}
		key, err := policy.LoadSigningKey(args[1])
		if err != nil {
			return err
		}
		if err := policy.SignPolicy(key, args[2]); err != nil {
			return err
		}
		fmt.Println("signed:", policy.SignatureFile(args[2]))
		return nil
	case "show":
		return apiGet(socket, "/v0/policy")
	case "reload":
		token, _ := flagOrFile(args[1:], "--token", "--token-file")
		return apiPost(socket, "/v0/policy/reload", token)
	default:
		return fmt.Errorf("unknown policy subcommand %q", args[0])
	}
}

// ---- admin ----

func centerCmd(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: edrctl center hosts|events --url U --secret S")
	}
	sub := args[0]
	rest := args[1:]
	url, rest := flagValue(rest, "--url")
	secret, rest := flagOrFile(rest, "--secret", "--secret-file")
	if url == "" || secret == "" {
		return fmt.Errorf("--url and --secret (or --secret-file) are required")
	}
	switch sub {
	case "hosts":
		return centerGet(url, "/v0/center/hosts", secret, "")
	case "events":
		host, rest := flagValue(rest, "--host")
		rule, rest := flagValue(rest, "--rule")
		limit, rest := flagValue(rest, "--limit")
		_ = rest
		q := "?"
		if host != "" {
			q += "host=" + host + "&"
		}
		if rule != "" {
			q += "rule_id=" + rule + "&"
		}
		if limit != "" {
			q += "limit=" + limit + "&"
		}
		return centerGet(url, "/v0/center/events", secret, strings.TrimRight(q, "&?"))
	case "correlations":
		limit, _ := flagValue(rest, "--limit")
		q := "?"
		if limit != "" {
			q += "limit=" + limit + "&"
		}
		return centerGet(url, "/v0/center/correlations", secret, strings.TrimRight(q, "&?"))
	case "cases":
		return centerCases(url, secret, rest)
	case "actions":
		return centerActions(url, secret, rest)
	case "report":
		return centerGet(url, "/v0/center/report", secret, "")
	case "export":
		format, rest := flagValue(rest, "--format")
		limit, _ := flagValue(rest, "--limit")
		q := "?"
		if format != "" {
			q += "format=" + format + "&"
		}
		if limit != "" {
			q += "limit=" + limit + "&"
		}
		return centerGet(url, "/v0/center/export", secret, strings.TrimRight(q, "&?"))
	default:
		return fmt.Errorf("unknown center subcommand %q", sub)
	}
}

func centerCases(url, secret string, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: edrctl center cases list|show|create|status|disposition")
	}
	switch args[0] {
	case "list":
		return centerGet(url, "/v0/center/cases", secret, "")
	case "show":
		if len(args) < 2 {
			return fmt.Errorf("case id required")
		}
		return centerGet(url, "/v0/center/cases/"+args[1], secret, "")
	case "create":
		title, rest := flagValue(args[1:], "--title")
		severity, rest := flagValue(rest, "--severity")
		rule, _ := flagValue(rest, "--rule")
		body := map[string]any{"title": title, "severity": severity}
		if rule != "" {
			body["rules"] = []string{rule}
		}
		return centerPost(url, "/v0/center/cases", secret, body)
	case "status":
		if len(args) < 3 {
			return fmt.Errorf("usage: center cases status <id> <new|triage|investigating|contained|closed>")
		}
		return centerPost(url, "/v0/center/cases/"+args[1]+"/status", secret, map[string]any{"status": args[2]})
	case "disposition":
		if len(args) < 3 {
			return fmt.Errorf("usage: center cases disposition <id> <true_positive|false_positive|benign>")
		}
		note, rest := flagValue(args[3:], "--note")
		_ = rest
		return centerPost(url, "/v0/center/cases/"+args[1]+"/disposition", secret, map[string]any{"disposition": args[2], "note": note})
	default:
		return fmt.Errorf("unknown cases subcommand %q", args[0])
	}
}

func centerActions(url, secret string, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: edrctl center actions list|show|create|approve|reject")
	}
	switch args[0] {
	case "list":
		return centerGet(url, "/v0/center/actions", secret, "")
	case "show":
		if len(args) < 2 {
			return fmt.Errorf("action id required")
		}
		return centerGet(url, "/v0/center/actions/"+args[1], secret, "")
	case "create":
		host, rest := flagValue(args[1:], "--host")
		action, rest := flagValue(rest, "--action")
		pid, rest := flagValue(rest, "--pid")
		path, rest := flagValue(rest, "--path")
		reason, _ := flagValue(rest, "--reason")
		body := map[string]any{"host": host, "action": action, "reason": reason}
		if pid != "" {
			var n int
			fmt.Sscanf(pid, "%d", &n)
			body["pid"] = n
		}
		if path != "" {
			body["path"] = path
		}
		return centerPost(url, "/v0/center/actions", secret, body)
	case "approve":
		if len(args) < 2 {
			return fmt.Errorf("action id required")
		}
		by, _ := flagValue(args[2:], "--by")
		return centerPost(url, "/v0/center/actions/"+args[1]+"/approve", secret, map[string]any{"by": by})
	case "reject":
		if len(args) < 2 {
			return fmt.Errorf("action id required")
		}
		by, rest := flagValue(args[2:], "--by")
		reason, _ := flagValue(rest, "--reason")
		return centerPost(url, "/v0/center/actions/"+args[1]+"/reject", secret, map[string]any{"by": by, "reason": reason})
	default:
		return fmt.Errorf("unknown actions subcommand %q", args[0])
	}
}

func centerPost(base, path, secret string, body any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, strings.TrimRight(base, "/")+path, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	requestauth.New([]byte(secret), 60*time.Second).Sign(req, raw, "", time.Now().UTC())
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(out)))
	}
	fmt.Println(strings.TrimRight(string(out), "\n"))
	return nil
}

func centerGet(base, path, secret, query string) error {
	req, err := http.NewRequest(http.MethodGet, strings.TrimRight(base, "/")+path+query, nil)
	if err != nil {
		return err
	}
	requestauth.New([]byte(secret), 60*time.Second).Sign(req, nil, "", time.Now().UTC())
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	fmt.Println(strings.TrimRight(string(body), "\n"))
	return nil
}

func adminCmd(args []string) error {
	if len(args) < 3 || args[0] != "token" {
		return fmt.Errorf("usage: edrctl admin token <action> --key-file F")
	}
	action := args[1]
	keyFile, _ := flagValue(args[2:], "--key-file")
	if keyFile == "" {
		return fmt.Errorf("--key-file required")
	}
	key, err := adminauth.LoadOrCreateKey(keyFile)
	if err != nil {
		return err
	}
	a := adminauth.New(key)
	token, exp, err := a.Issue(action, time.Now())
	if err != nil {
		return err
	}
	fmt.Println(token)
	fmt.Fprintf(os.Stderr, "expires_at=%d\n", exp)
	return nil
}
