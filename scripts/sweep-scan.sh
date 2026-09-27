#!/usr/bin/env bash
# sweeps scan thresholds against a benign burst and two scan speeds
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "run with sudo"; exit 1; }

ATTACKER="${ATTACKER:-10.10.10.20}"
ATTACKER_USER="${ATTACKER_USER:-apiary}"
LOADER="${LOADER:-/tmp/apiary-loader}"
DECOY="${DECOY:-ap-dionaea}"
OUT="${OUT:-docs/evidence/scan-sweep.csv}"
PORTS_LIST="${PORTS_LIST:-5 10 20 40}"
WINDOW_LIST="${WINDOW_LIST:-2 10 30}"

[[ -x "$LOADER" ]] || { echo "no loader at $LOADER"; exit 1; }

APIARY_IFACE="br-$(docker network inspect -f '{{.Id}}' apiary-net | cut -c1-12)"
export APIARY_IFACE
decoy_ip=$(docker inspect -f "{{(index .NetworkSettings.Networks \"apiary-net\").IPAddress}}" "$DECOY")

remote() { sudo -u "${SUDO_USER:-$USER}" ssh -o BatchMode=yes "$ATTACKER_USER@$ATTACKER" "$1" >/dev/null 2>&1 || true; }

benign() { remote "for p in 21 42 80 135 443 445 1433 3306; do timeout 1 bash -c \"exec 3<>/dev/tcp/$decoy_ip/\$p\"; sleep 2; done"; }
fast()   { remote "nmap -sT -p 1-200 --max-retries 0 $decoy_ip"; }
slow()   { remote "nmap -sT -p 1-25 --scan-delay 1s --max-retries 0 $decoy_ip"; }

trial() {
  "$LOADER" -scan-ports "$1" -scan-window "$2" >/tmp/sweep.log 2>&1 &
  local pid=$! hit=0
  sleep 2
  "$3"
  sleep 1
  grep -q "flagged $ATTACKER" /tmp/sweep.log && hit=1
  kill -INT "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
  echo "$hit"
}

echo "ports,window,benign,fast,slow" > "$OUT"
for n in $PORTS_LIST; do
  for t in $WINDOW_LIST; do
    b=$(trial "$n" "$t" benign)
    f=$(trial "$n" "$t" fast)
    s=$(trial "$n" "$t" slow)
    echo "$n,$t,$b,$f,$s" | tee -a "$OUT"
  done
done
echo "written to $OUT"
