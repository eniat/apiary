#!/usr/bin/env bash
set -euo pipefail

LAB_NET="${LAB_NET:-10.10.10.0/24}"
HP_NET="${HP_NET:-172.30.0.0/16}"

add() {
  local table=$1; shift
  sudo iptables -t "$table" -C "$@" 2>/dev/null || sudo iptables -t "$table" -I "$@"
}

add filter DOCKER-USER -s "$LAB_NET" -d "$HP_NET" -j ACCEPT

echo "lab rules applied"
