#!/usr/bin/env bash

set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "run with sudo"; exit 1; }
IFACE="${IFACE:-br-$(docker network inspect -f '{{.Id}}' apiary-net | cut -c1-12)}"
tc qdisc del dev "$IFACE" clsact 2>/dev/null || true
echo "detached $IFACE"
