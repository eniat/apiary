#!/usr/bin/env bash
# sit on the scaling threshold so the policy has to keep choosing
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "run with sudo"; exit 1; }

ATTACKER="${ATTACKER:-10.10.10.20}"
ATTACKER_USER="${ATTACKER_USER:-apiary}"
DARK="${DARK:-172.30.99.10}"
TARGET="${TARGET:-10.10.10.10}"
PORT="${PORT:-2222}"
TICK="${TICK:-5}"
ROUNDS="${ROUNDS:-24}"
SEED="${SEED:-7}"

remote() { sudo -u "${SUDO_USER:-$USER}" ssh -o BatchMode=yes -o ConnectTimeout=10 "$ATTACKER_USER@$ATTACKER" "$1"; }

# one dark touch flags the source. every syn after it counts as unserved
remote "timeout 2 bash -c 'exec 3<>/dev/tcp/$DARK/$PORT' || true" >/dev/null 2>&1
echo "flagged $ATTACKER"

# the whole loop runs on the attacker. an ssh hop per round would swamp the tick
remote "RANDOM=$SEED
for i in \$(seq 1 $ROUNDS); do
  n=\$((RANDOM % 4 + 1))
  for _ in \$(seq 1 \$n); do timeout 1 bash -c 'exec 3<>/dev/tcp/$TARGET/$PORT' || true; done
  echo \"round \$i sent \$n\"
  sleep $TICK
done"
