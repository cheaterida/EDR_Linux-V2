#!/bin/bash
# M7 HA smoke test: two orchestrators watch a stale peer; only one (lease
# holder) restarts it; when the peer recovers the lease is released.
set -u
RUN=/tmp/edr-ha
rm -rf "$RUN"
mkdir -p "$RUN"
# stale peer heartbeat => "down"
echo "{\"instance_id\":\"edr-b\",\"unix\":$(( $(date +%s) - 100 ))}" > "$RUN/edr-b.heartbeat"

chmod +x /tmp/edr-orchestrator /tmp/m7_recover_peer.sh

/tmp/edr-orchestrator --instance edr-a --peer edr-b --run-dir "$RUN" \
    --interval 1s --suspect-after 3 --down-after 5 --lease-ttl 10s --restart-cooldown 10s \
    --restart-cmd "/tmp/m7_recover_peer.sh" --run-for 16s >/tmp/oa.log 2>&1 &
/tmp/edr-orchestrator --instance edr-c --peer edr-b --run-dir "$RUN" \
    --interval 1s --suspect-after 3 --down-after 5 --lease-ttl 10s --restart-cooldown 10s \
    --restart-cmd "/tmp/m7_recover_peer.sh" --run-for 16s >/tmp/oc.log 2>&1 &

wait
echo "=== orchestrator edr-a ==="; cat /tmp/oa.log
echo "=== orchestrator edr-c ==="; cat /tmp/oc.log
echo "=== files ==="; ls -1 "$RUN"
echo "=== restarts (should be exactly one) ==="
grep -c "acquired; restarting" /tmp/oa.log /tmp/oc.log
echo DONE
