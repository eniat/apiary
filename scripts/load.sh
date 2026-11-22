#!/usr/bin/env bash
# synthetic load shapes
set -euo pipefail

ATTACKER="${ATTACKER:-10.10.10.20}"
ATTACKER_USER="${ATTACKER_USER:-apiary}"
DARK="${DARK:-172.30.99.10}"
TARGET="${TARGET:-10.10.10.10}"
PORT="${PORT:-2222}"
TICK="${TICK:-5}"
ROUNDS="${ROUNDS:-24}"
SEED="${SEED:-7}"
PEAK="${PEAK:-5}"
LOW="${LOW:-0}"
PERIOD="${PERIOD:-1}"
PROFILE="${PROFILE:-threshold}"
DRY="${DRY:-0}"

remote() { sudo -u "${SUDO_USER:-$USER}" ssh -o BatchMode=yes -o ConnectTimeout=10 "$ATTACKER_USER@$ATTACKER" "$1"; }

# shape built locally so runs repeat
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
    step)
      if (( i > ROUNDS / 3 )); then n=$PEAK; else n=0; fi
      ;;
    sustained) n=$PEAK ;;
    oscillating)
      if (( (i - 1) / PERIOD % 2 == 0 )); then n=$PEAK; else n=$LOW; fi
      ;;
    quiet) n=0 ;;
    *) echo "unknown profile $PROFILE, want threshold ramp spike step sustained oscillating or quiet"; exit 1 ;;
  esac
  shape="$shape $n"
done

echo "profile $PROFILE rounds $ROUNDS tick ${TICK}s"
echo "syns per round:$shape"
[[ "$DRY" == 1 ]] && exit 0

[[ $EUID -eq 0 ]] || { echo "run with sudo"; exit 1; }

# dark touch flags the source
remote "timeout 0.5 bash -c 'exec 3<>/dev/tcp/$DARK/$PORT' || true" >/dev/null 2>&1
echo "flagged $ATTACKER"

# one hop with rounds on fixed deadlines
remote "bash -s" <<EOF
t0=\${EPOCHREALTIME/./}
i=0
for n in$shape; do
  echo "\$(( (\${EPOCHREALTIME/./} - t0) / 1000 ))ms sending \$n"
  ( for _ in \$(seq 1 \$n); do timeout 1 bash -c 'exec 3<>/dev/tcp/$TARGET/$PORT' || true; done ) &
  i=\$(( i + 1 ))
  d=\$(( t0 + i * $TICK * 1000000 - \${EPOCHREALTIME/./} ))
  printf -v f %06d \$(( d % 1000000 ))
  (( d > 0 )) && sleep \$(( d / 1000000 )).\$f
done
wait
EOF
