#!/usr/bin/env bash
# cowrie rotates its json daily but never removes old files
# the host log root keeps a directory per honeypot ever created
# log dirs are owned by the container uid so this needs root
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "run with sudo"; exit 1; }
RETAIN_DAYS="${RETAIN_DAYS:-14}"
root="$(cd "$(dirname "$0")/.." && pwd)"
LOG_ROOT="${LOG_ROOT:-/var/lib/apiary/logs}"
ARCHIVE="${ARCHIVE:-/var/lib/apiary/archive}"
ARCHIVE_DAYS="${ARCHIVE_DAYS:-0}"

log_dir="$root/honeypots/cowrie/data/log"
[[ -d "$log_dir" ]] || { echo "no log dir at $log_dir"; exit 1; }
find "$log_dir" -maxdepth 1 -name 'cowrie.json.*' -mtime "+$RETAIN_DAYS" -print -delete

# a honeypot's live logs go once the archive holds them and the window passes
if [[ -d "$LOG_ROOT" ]]; then
  while IFS= read -r d; do
    name="$(basename "$d")"
    if docker inspect "$name" >/dev/null 2>&1; then continue; fi
    echo "pruning $d"
    rm -rf "$d"
  done < <(find "$LOG_ROOT" -mindepth 1 -maxdepth 1 -type d -name 'ap-hp-*' -mtime "+$RETAIN_DAYS")
fi

if [[ "$ARCHIVE_DAYS" -gt 0 && -d "$ARCHIVE" ]]; then
  find "$ARCHIVE" -mindepth 1 -maxdepth 1 -type d -mtime "+$ARCHIVE_DAYS" -print -exec rm -rf {} +
else
  echo "archive kept, set ARCHIVE_DAYS to prune it"
fi

# dionaea's sqlite is sized not trimmed, it holds captured artefacts
db="$root/honeypots/dionaea/data/lib/dionaea.sqlite"
[[ -f "$db" ]] && echo "dionaea db: $(du -h "$db" | cut -f1)" || true
