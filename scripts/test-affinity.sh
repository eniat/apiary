#!/usr/bin/env bash
# affinity must survive another honeypot being created and another being destroyed
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "run with sudo"; exit 1; }

ATTACKER="${ATTACKER:-10.10.10.20}"
ATTACKER_USER="${ATTACKER_USER:-apiary}"
LOADER="${LOADER:-/tmp/apiary-loader}"
REAP="${REAP:-/tmp/apiary-reap}"
POOL="${POOL:-/tmp/apiary-pool}"
DECOY="${DECOY:-ap-cowrie}"
PORT="${PORT:-2222}"
GRACE="${GRACE:-15s}"
AFFINITY="${AFFINITY:-3m}"
LOGROOT="${LOGROOT:-/var/lib/apiary/logs}"

for b in "$LOADER" "$REAP" "$POOL"; do
  [[ -x "$b" ]] || { echo "no binary at $b, use make test-affinity"; exit 1; }
done

remote() { sudo -u "${SUDO_USER:-$USER}" ssh -o BatchMode=yes -o ConnectTimeout=10 "$ATTACKER_USER@$ATTACKER" "$1"; }
sweep() { docker ps -aq --filter name=ap-hp- | xargs -r docker rm -f >/dev/null 2>&1 || true; }
reaped() { grep -qE 'reaped [1-9]' /tmp/apiary-reap.log; }
sessions_in() {
  tr -d '\0' < "$1" 2>/dev/null | jq -rR --arg ip "$ATTACKER" \
    'fromjson? | select(.eventid=="cowrie.session.connect" and .src_ip==$ip) | .session' | wc -l
}
cleanup() {
  kill -INT "$reap" "$loader" 2>/dev/null || true
  sleep 1
  sweep
}

# leftovers from an earlier run would mask what this one does
sweep

APIARY_IFACE="br-$(docker network inspect -f '{{.Id}}' apiary-net | cut -c1-12)"
export APIARY_IFACE

decoy_ip=$(docker inspect -f "{{(index .NetworkSettings.Networks \"apiary-net\").IPAddress}}" "$DECOY")
echo "decoy $DECOY $decoy_ip"

"$LOADER" -lab enp0s8 >/tmp/apiary-loader.log 2>&1 &
loader=$!
"$REAP" -grace "$GRACE" -affinity "$AFFINITY" -ticks 60 >/tmp/apiary-reap.log 2>&1 &
reap=$!
trap cleanup EXIT

sleep 2
kill -0 "$loader" 2>/dev/null || { echo "loader died"; cat /tmp/apiary-loader.log; exit 1; }

for _ in $(seq 1 60); do
  grep -q '^registered ' /tmp/apiary-reap.log && break
  sleep 1
done
hp=$(awk '/^registered /{print $4}' /tmp/apiary-reap.log)
[[ -n "$hp" ]] || { echo "FAIL nothing registered"; cat /tmp/apiary-reap.log; exit 1; }
echo "bound $ATTACKER to $hp"

key() { remote "ssh-keyscan -p $PORT -t ed25519 $decoy_ip 2>/dev/null | awk '{print \$3}'"; }

k1=$(key)
[[ -n "$k1" ]] || { echo "FAIL no host key before the scale events"; exit 1; }
echo "PASS first key seen"

# scale up. more containers created while the engagement is live
"$POOL" -n 2 -keep >/tmp/apiary-pool.log 2>&1
k2=$(key)
[[ "$k2" == "$k1" ]] || { echo "FAIL key changed across a scale up"; exit 1; }
echo "PASS key held across a scale up"

# scale down. read the reapers own log rather than counting containers
for _ in $(seq 1 90); do
  reaped && break
  sleep 1
done
reaped || { echo "FAIL nothing was reaped in time"; tail -5 /tmp/apiary-reap.log; exit 1; }
echo "PASS a honeypot was reaped during the engagement"

[[ "$(docker inspect -f '{{.State.Running}}' "$hp" 2>/dev/null)" == "true" ]] || { echo "FAIL the bound honeypot was destroyed"; exit 1; }
echo "PASS the bound honeypot survived"

k3=$(key)
[[ "$k3" == "$k1" ]] || { echo "FAIL key changed across a scale down"; exit 1; }
echo "PASS key held across a scale down"

n=$(sessions_in "$LOGROOT/$hp/log/cowrie.json")
[[ "$n" -ge 3 ]] || { echo "FAIL $hp saw $n sessions, want at least 3"; exit 1; }
echo "PASS $hp holds all $n sessions"

strays=0
for d in "$LOGROOT"/ap-hp-*; do
  id=$(basename "$d")
  [[ "$id" == "$hp" ]] && continue
  docker inspect "$id" >/dev/null 2>&1 || continue
  strays=$((strays + $(sessions_in "$d/log/cowrie.json")))
done
[[ "$strays" -eq 0 ]] || { echo "FAIL $strays sessions landed elsewhere"; exit 1; }
echo "PASS nothing landed elsewhere"
