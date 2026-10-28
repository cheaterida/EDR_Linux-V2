// Command edr-orchestrator is the HA failover loop. It publishes a heartbeat,
// watches a peer's heartbeat, and when the peer is down it takes a lease and
// restarts it (locally, or after asking the supervisor for a quorum decision).
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"edr/internal/lease"
	"edr/internal/liveness"
	"edr/internal/requestauth"
	"edr/internal/supervisor"
)

var version = "v2.0.0-m7"

func main() {
	runDir := flag.String("run-dir", "/run/edr", "directory for heartbeats and leases")
	instance := flag.String("instance", "edr-a", "this instance id")
	peer := flag.String("peer", "edr-b", "peer instance id")
	interval := flag.Duration("interval", time.Second, "heartbeat/scan interval")
	suspectAfter := flag.Int("suspect-after", 3, "suspect after N intervals")
	downAfter := flag.Int("down-after", 5, "down after N intervals")
	leaseTTL := flag.Duration("lease-ttl", 10*time.Second, "lease TTL")
	restartCooldown := flag.Duration("restart-cooldown", 30*time.Second, "minimum interval between restart attempts")
	restartCmd := flag.String("restart-cmd", "", "shell command (space-split) to restart the peer")
	supURL := flag.String("supervisor-url", "", "supervisor heartbeat endpoint (optional quorum)")
	sharedSecret := flag.String("shared-secret", "", "shared secret for supervisor auth")
	runFor := flag.Duration("run-for", 0, "stop after this duration")
	flag.Parse()

	ctx := context.Background()
	if *runFor > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, *runFor)
		defer cancel()
	}

	var auth *requestauth.Authenticator
	sendSupervisor := func(hb liveness.Heartbeat, peerState string) *supervisor.RestartIntent {
		if *supURL == "" {
			return nil
		}
		if auth == nil {
			auth = requestauth.New([]byte(*sharedSecret), 30*time.Second)
		}
		reqBody, _ := json.Marshal(supervisor.HeartbeatRequest{
			InstanceID: *instance, PeerInstanceID: *peer, PeerState: peerState,
			SentAt: time.Now().UTC(), Local: hb, Hostname: hostname(),
		})
		httpReq, err := http.NewRequest(http.MethodPost, *supURL, bytes.NewReader(reqBody))
		if err != nil {
			return nil
		}
		httpReq.Header.Set("Content-Type", "application/json")
		auth.Sign(httpReq, reqBody, "", time.Now().UTC())
		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Do(httpReq)
		if err != nil {
			fmt.Fprintf(os.Stderr, "orchestrator: supervisor: %v\n", err)
			return nil
		}
		defer resp.Body.Close()
		var out supervisor.HeartbeatResponse
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			return nil
		}
		return out.RestartIntent
	}

	_ = liveness.Write(*runDir, liveness.Heartbeat{InstanceID: *instance, Unix: time.Now().Unix()})
	fmt.Fprintf(os.Stderr, "orchestrator %s: instance=%s peer=%s run_dir=%s\n", version, *instance, *peer, *runDir)

	ticker := time.NewTicker(*interval)
	defer ticker.Stop()
	var restartGen uint64
	var heldLease string
	var lastRestart time.Time

	for {
		select {
		case <-ctx.Done():
			fmt.Fprintln(os.Stderr, "orchestrator: stopped")
			return
		case <-ticker.C:
		}

		now := time.Now()
		hb := liveness.Heartbeat{InstanceID: *instance, Unix: now.Unix(), LeaseID: heldLease, RestartGeneration: restartGen}
		_ = liveness.Write(*runDir, hb)

		state := "starting"
		if peerHB, err := liveness.Read(*runDir, *peer); err == nil {
			state = liveness.State(now, peerHB, *suspectAfter, *downAfter, *interval)
		}

		intent := sendSupervisor(hb, state)

		switch {
		case state == "down" || intent != nil:
			if state != "down" && intent != nil {
				fmt.Fprintf(os.Stderr, "orchestrator: supervisor issued restart intent for %s (%s)\n", intent.Target, intent.Reason)
			}
			l, err := lease.Acquire(*runDir, *peer, *instance, *leaseTTL, now)
			if err == lease.ErrHeld {
				continue
			}
			if err != nil {
				continue
			}
			if heldLease == "" {
				heldLease = l.LeaseID
			}
			// Only act once per cooldown window; while holding the lease we
			// merely refresh it (the peer may still be coming up).
			if now.Sub(lastRestart) < *restartCooldown {
				continue
			}
			lastRestart = now
			restartGen++
			fmt.Fprintf(os.Stderr, "orchestrator: peer %s down; lease %s acquired; restarting\n", *peer, l.LeaseID)
			if *restartCmd != "" {
				runRestart(*restartCmd)
			}
		case state == "healthy":
			if heldLease != "" {
				_ = lease.Release(*runDir, *peer, heldLease)
				fmt.Fprintf(os.Stderr, "orchestrator: peer %s healthy; lease released\n", *peer)
				heldLease = ""
			}
		}
	}
}

func runRestart(cmdline string) {
	parts := strings.Fields(cmdline)
	if len(parts) == 0 {
		return
	}
	cmd := exec.Command(parts[0], parts[1:]...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Fprintf(os.Stderr, "orchestrator: restart command failed: %v (%s)\n", err, strings.TrimSpace(string(out)))
	}
}

func hostname() string {
	h, _ := os.Hostname()
	return h
}
