#!/usr/bin/env bash
# a dark touch flags the attacker then its next connection lands on a honeypot
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "run with sudo"; exit 1; }

ATTACKER="${ATTACKER:-10.10.10.20}"
ATTACKER_USER="${ATTACKER_USER:-apiary}"
LOADER="${LOADER:-/tmp/apiary-loader}"
HP="${HP:-ap-cowrie}"
DECOY="${DECOY:-ap-dionaea}"
PORT="${PORT:-2222}"
DARK="${DARK:-172.30.99.10}"
LOG="${LOG:-honeypots/cowrie/data/log/cowrie.json}"

[[ -x "$LOADER" ]] || { echo "no loader at $LOADER, use make test-detect"; exit 1; }
[[ -f "$LOG" ]] || { echo "no cowrie log at $LOG"; exit 1; }

netfield() { docker inspect -f "{{(index .NetworkSettings.Networks \"apiary-net\").$2}}" "$1"; }
remote() { sudo -u "${SUDO_USER:-$USER}" ssh -o BatchMode=yes -o ConnectTimeout=10 "$ATTACKER_USER@$ATTACKER" "$1"; }

APIARY_IFACE="br-$(docker network inspect -f '{{.Id}}' apiary-net | cut -c1-12)"
export APIARY_IFACE

for c in "$HP" "$DECOY"; do
  [[ "$(docker inspect -f '{{.State.Running}}' "$c" 2>/dev/null)" == "true" ]] || { echo "$c not running"; exit 1; }
done

hp_ip=$(netfield "$HP" IPAddress)
hp_mac=$(netfield "$HP" MacAddress)
hp_if=$(cat "/proc/$(docker inspect -f '{{.State.Pid}}' "$HP")/root/sys/class/net/eth0/iflink")
decoy_ip=$(netfield "$DECOY" IPAddress)

echo "$ATTACKER touches $DARK then dials $decoy_ip:$PORT, expect a session on $HP $hp_ip"

"$LOADER" -dst "$hp_ip" -mac "$hp_mac" -ifindex "$hp_if" >/tmp/apiary-loader.log 2>&1 &
loader=$!
trap 'kill -INT "$loader" 2>/dev/null || true' EXIT
sleep 2
kill -0 "$loader" 2>/dev/null || { echo "loader died"; cat /tmp/apiary-loader.log; exit 1; }

# nothing is flagged yet so this must reach the decoy and not the honeypot
early=$(remote "timeout 5 bash -c 'exec 3<>/dev/tcp/$decoy_ip/$PORT; read -r -t 3 l <&3; printf %s \"\$l\"'" || true)
[[ "$early" != SSH-* ]] || { echo "FAIL banner before any dark touch"; exit 1; }
echo "PASS no banner before the dark touch"

t0=$(date -u +%s)
remote "timeout 5 bash -c 'exec 3<>/dev/tcp/$DARK/$PORT' || true" >/dev/null 2>&1
sleep 1
grep -q "registered $ATTACKER" /tmp/apiary-loader.log || { echo "FAIL $ATTACKER not registered"; cat /tmp/apiary-loader.log; exit 1; }
echo "PASS registered after the dark touch"

banner=$(remote "timeout 10 bash -c 'exec 3<>/dev/tcp/$decoy_ip/$PORT; read -r -t 5 l <&3; printf %s \"\$l\"'" || true)
[[ "$banner" == SSH-* ]] || { echo "FAIL no banner from $decoy_ip:$PORT, got '$banner'"; exit 1; }
echo "PASS banner $banner"

sleep 2
sid=$(tr -d '\0' < "$LOG" | jq -rR --arg ip "$ATTACKER" --argjson t0 "$t0" \
  'fromjson? | select(.eventid=="cowrie.session.connect" and .src_ip==$ip
   and ((.timestamp[0:19]+"Z")|fromdateiso8601) >= $t0) | .session' | tail -1)
[[ -n "$sid" ]] || { echo "FAIL no cowrie session from $ATTACKER"; exit 1; }
echo "PASS cowrie session $sid from $ATTACKER"
