#!/usr/bin/env bash
# a repeatable nmap scan from the attacker against a target in the lab
# runs entirely on the attacker in one hop so the six second ssh is paid once
# sT is the default because it needs no privilege, sS needs root on the attacker
set -euo pipefail

ATTACKER="${ATTACKER:-10.10.10.20}"
ATTACKER_USER="${ATTACKER_USER:-apiary}"
TARGET="${TARGET:-}"
PORTS="${PORTS:-1-1000}"
SCAN="${SCAN:-sT}"
TIMING="${TIMING:-4}"
OUT="${OUT:-docs/evidence/scan-$SCAN-T$TIMING.txt}"

[[ -n "$TARGET" ]] || { echo "set TARGET to a honeypot address on apiary-net"; exit 1; }

# a raw scan needs root, which over a batch ssh means passwordless sudo on the attacker
case "$SCAN" in
  sT|sV) priv="" ;;
  *)     priv="sudo " ;;
esac

remote() { ssh -o BatchMode=yes -o ConnectTimeout=10 "$ATTACKER_USER@$ATTACKER" "$1"; }

# oG is grepable and deterministic, the run header carries the parameters
cmd="${priv}nmap -$SCAN -p $PORTS -T$TIMING --max-retries 1 -oG - $TARGET"
echo "# $cmd" | tee "$OUT"
remote "$cmd" | grep -v '^#' | tee -a "$OUT"
