#!/usr/bin/env bash
# synthetic attack load in named shapes
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
PEAK="${PEAK:-5}"
PROFILE="${PROFILE:-threshold}"

remote() { sudo -u "${SUDO_USER:-$USER}" ssh -o BatchMode=yes -o ConnectTimeout=10 "$ATTACKER_USER@$ATTACKER" "$1"; }

# the shape is built here so the run is visible and repeatable
RANDOM="$SEED"
half=$(( ROUNDS / 2 ))
shape=""
for (( i = 1; i <= ROUNDS; i++ )); do
  case "$PROFILE" in
    threshold) n=$(( RANDOM % 4 + 1 )) ;;
    ramp)
      if (( i <= half )); then n=$(( PEAK * i / half )); else n=$(( PEAK * (ROUNDS - i) / half )); fi
      ;;
    spike)
      if (( i > ROUNDS / 3 && i <= 2 * ROUNDS / 3 )); then n=$PEAK; else n=0; fi
      ;;
    quiet) n=0 ;;
    *) echo "unknown profile $PROFILE, want threshold ramp spike or quiet"; exit 1 ;;
  esac
  shape="$shape $n"
done

echo "profile $PROFILE rounds $ROUNDS tick ${TICK}s"
echo "syns per round:$shape"

# one dark touch flags the source. every syn after it counts as unserved
remote "timeout 2 bash -c 'exec 3<>/dev/tcp/$DARK/$PORT' || true" >/dev/null 2>&1
echo "flagged $ATTACKER"

# the whole loop runs on the attacker. an ssh hop per round would swamp the tick
remote "for n in$shape; do
  for _ in \$(seq 1 \$n); do timeout 1 bash -c 'exec 3<>/dev/tcp/$TARGET/$PORT' || true; done
  echo \"sent \$n\"
  sleep $TICK
done"
