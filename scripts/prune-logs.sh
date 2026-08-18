#!/usr/bin/env bash
# cowrie rotates its json daily but never removes old files
# log dir owned by the container's uid so needs root
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "run with sudo"; exit 1; }
RETAIN_DAYS="${RETAIN_DAYS:-14}"
root="$(cd "$(dirname "$0")/.." && pwd)"
log_dir="$root/honeypots/cowrie/data/log"
[[ -d "$log_dir" ]] || { echo "no log dir at $log_dir"; exit 1; }
find "$log_dir" -maxdepth 1 -name 'cowrie.json.*' -mtime "+$RETAIN_DAYS" -print -delete
# dionaea's sqlite is sized, not trimmed. it holds captured artefacts
db="$root/honeypots/dionaea/data/lib/dionaea.sqlite"
[[ -f "$db" ]] && echo "dionaea db: $(du -h "$db" | cut -f1)" || true
