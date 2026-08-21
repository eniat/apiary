#!/usr/bin/env bash
# runs the hosts networking tools inside containers netns so image
# does not need them. cowrie has no cat or id and still works
set -euo pipefail
container="${1:?usage: netns-peek.sh <container>}"

pid=$(docker inspect -f '{{.State.Pid}}' "$container")
[[ "$pid" != "0" ]] || { echo "$container is not running"; exit 1; }

echo "== $container (pid $pid)"
sudo nsenter -t "$pid" -n ip -brief addr
echo
sudo nsenter -t "$pid" -n ip route
echo
sudo nsenter -t "$pid" -n ss -lntp
