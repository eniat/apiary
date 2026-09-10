#!/usr/bin/env bash
# asserts on the syn-ack, a full session needs the return path
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "run with sudo"; exit 1; }

ATTACKER="${ATTACKER:-10.10.10.20}"
ATTACKER_USER="${ATTACKER_USER:-apiary}"
LOADER="${LOADER:-/tmp/apiary-loader}"
HP="${HP:-ap-cowrie}"
DECOY="${DECOY:-ap-dionaea}"
PORT="${PORT:-2222}"

[[ -x "$LOADER" ]] || { echo "no loader at $LOADER, use make test-redirect"; exit 1; }

netfield() { docker inspect -f "{{(index .NetworkSettings.Networks \"apiary-net\").$2}}" "$1"; }

APIARY_IFACE="br-$(docker network inspect -f '{{.Id}}' apiary-net | cut -c1-12)"
export APIARY_IFACE

for c in "$HP" "$DECOY"; do
  [[ "$(docker inspect -f '{{.State.Running}}' "$c" 2>/dev/null)" == "true" ]] || { echo "$c not running"; exit 1; }
done

hp_ip=$(netfield "$HP" IPAddress)
hp_mac=$(netfield "$HP" MacAddress)
hp_if=$(cat "/proc/$(docker inspect -f '{{.State.Pid}}' "$HP")/root/sys/class/net/eth0/iflink")
decoy_ip=$(netfield "$DECOY" IPAddress)
veth=$(ip -o link | awk -F'[: @]+' -v i="$hp_if" '$1==i {print $2}')

echo "$ATTACKER -> $decoy_ip:$PORT, expect $hp_ip answering on $veth"

"$LOADER" -src "$ATTACKER" -dst "$hp_ip" -mac "$hp_mac" -ifindex "$hp_if" \
  >/tmp/apiary-loader.log 2>&1 &
loader=$!
trap 'kill -INT "$loader" 2>/dev/null || true' EXIT
sleep 2
kill -0 "$loader" 2>/dev/null || { echo "loader died"; cat /tmp/apiary-loader.log; exit 1; }

# syn and ack both set
timeout 20 tcpdump -ni "$veth" -c 1 \
  "src host $hp_ip and tcp src port $PORT and tcp[13] & 0x12 == 0x12" \
  >/tmp/apiary-capture.log 2>&1 &
cap=$!
sleep 1

sudo -u "${SUDO_USER:-$USER}" ssh -o BatchMode=yes -o ConnectTimeout=5 \
  "$ATTACKER_USER@$ATTACKER" \
  "timeout 5 bash -c 'exec 3<>/dev/tcp/$decoy_ip/$PORT' || true"

if wait "$cap"; then
  echo "PASS syn-ack from $hp_ip"
else
  echo "FAIL no syn-ack from $hp_ip"
  cat /tmp/apiary-capture.log
  exit 1
fi
