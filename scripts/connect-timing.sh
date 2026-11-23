#!/usr/bin/env bash
# tcp connect time from the attacker direct and through the redirect
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "run with sudo"; exit 1; }

ATTACKER="${ATTACKER:-10.10.10.20}"
ATTACKER_USER="${ATTACKER_USER:-apiary}"
LOADER="${LOADER:-/tmp/apiary-loader}"
HP="${HP:-ap-cowrie}"
DECOY="${DECOY:-ap-dionaea}"
PORT="${PORT:-2222}"
N="${N:-200}"
RUNS="${RUNS:-2}"

netfield() { docker inspect -f "{{(index .NetworkSettings.Networks \"apiary-net\").$2}}" "$1"; }
remote() { sudo -u "${SUDO_USER:-$USER}" ssh -o BatchMode=yes -o ConnectTimeout=10 "$ATTACKER_USER@$ATTACKER" "$1"; }

APIARY_IFACE="br-$(docker network inspect -f '{{.Id}}' apiary-net | cut -c1-12)"
export APIARY_IFACE

hp_ip=$(netfield "$HP" IPAddress)
hp_mac=$(netfield "$HP" MacAddress)
hp_if=$(cat "/proc/$(docker inspect -f '{{.State.Pid}}' "$HP")/root/sys/class/net/eth0/iflink")
decoy_ip=$(netfield "$DECOY" IPAddress)

# microseconds to established on the attacker clock
probe() {
  remote "bash -s" <<EOF
for i in \$(seq 1 $N); do
  t=\${EPOCHREALTIME/./}
  exec 3<>/dev/tcp/$1/$PORT
  e=\${EPOCHREALTIME/./}
  exec 3>&-
  echo \$(( e - t ))
  sleep 0.05
done
EOF
}

loader=""
stop() { if [[ -n "$loader" ]]; then kill "$loader"; wait "$loader" || true; loader=""; fi; }
trap stop EXIT

echo "path,run,us"
for (( r = 1; r <= RUNS; r++ )); do
  probe "$hp_ip" | sed "s/^/direct,$r,/"
  "$LOADER" -src "$ATTACKER" -dst "$hp_ip" -mac "$hp_mac" -ifindex "$hp_if" >/tmp/apiary-loader.log 2>&1 &
  loader=$!
  sleep 2
  probe "$decoy_ip" | sed "s/^/redirect,$r,/"
  stop
done
