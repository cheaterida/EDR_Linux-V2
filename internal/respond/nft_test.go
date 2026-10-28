package respond

import "testing"

func TestNFTBlockRejectsInjection(t *testing.T) {
	p := NFTProvider{DryRun: true}
	// A malicious "address" must be rejected before any nft invocation.
	if r := p.ApplyBlock(Request{Action: ActionNFTBlock, RemoteAddr: "1.2.3.4; reboot"}); r.Success {
		t.Fatalf("injection address accepted: %+v", r)
	}
}

func TestNFTDryRunNeverEnforces(t *testing.T) {
	p := NFTProvider{DryRun: true}
	r := p.ApplyBlock(Request{Action: ActionNFTBlock, RemoteAddr: "10.0.0.1", RemotePort: 4444})
	if !r.Success || r.Enforced {
		t.Fatalf("nft dry-run block wrong: %+v", r)
	}
	if r := p.ApplyIsolate(); !r.Success || r.Enforced {
		t.Fatalf("nft dry-run isolate wrong: %+v", r)
	}
	if r := p.Rollback(); !r.Success || r.Enforced {
		t.Fatalf("nft dry-run rollback wrong: %+v", r)
	}
}

func TestNFTBlockAcceptsValidAddr(t *testing.T) {
	p := NFTProvider{Enabled: false, DryRun: true}
	r := p.ApplyBlock(Request{Action: ActionNFTBlock, RemoteAddr: "10.0.0.1", Protocol: "tcp"})
	if !r.Success {
		t.Fatalf("valid address rejected: %+v", r)
	}
}
