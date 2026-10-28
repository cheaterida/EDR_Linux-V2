#!/bin/bash
# Simulated peer recovery: after a short delay, publish fresh heartbeats for
# edr-b continuously (in the background) so the peer stays healthy.
(
  sleep 2
  for i in $(seq 1 60); do
    echo "{\"instance_id\":\"edr-b\",\"unix\":$(date +%s),\"restart_generation\":1}" > /tmp/edr-ha/edr-b.heartbeat
    sleep 1
  done
) >/dev/null 2>&1 &
exit 0
