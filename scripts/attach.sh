#!/usr/bin/env bash
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "run with sudo"; exit 1; }
root="$(cd "$(dirname "$0")/.." && pwd)"
OBJ="${OBJ:-$root/dataplane/redirect.bpf.o}"
IFACE="${IFACE:-br-$(docker network inspect -f '{{.Id}}' apiary-net | cut -c1-12)}"
DIRS="${DIRS:-ingress egress}"
[[ -f "$OBJ" ]] || { echo "no object at $OBJ, run make bpf"; exit 1; }
tc qdisc show dev "$IFACE" | grep -q clsact || tc qdisc add dev "$IFACE" clsact
for d in $DIRS; do
  tc filter del dev "$IFACE" "$d" 2>/dev/null || true
  tc filter add dev "$IFACE" "$d" bpf da obj "$OBJ" sec tc
done
echo "attached $OBJ to $IFACE ($DIRS)"
