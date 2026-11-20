#!/usr/bin/env bash
# dionaea writes sqlite so it cant be tailed
# each table is polled past its own watermark and appended as json lines
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "run with sudo"; exit 1; }

root="$(cd "$(dirname "$0")/.." && pwd)"
DB="${DB:-$root/honeypots/dionaea/data/lib/dionaea.sqlite}"
OUT_DIR="${OUT_DIR:-/var/lib/apiary/logs/ap-dionaea/log}"
STATE_DIR="${STATE_DIR:-/var/lib/apiary/flb/dionaea}"

[[ -f "$DB" ]] || { echo "no db at $DB"; exit 1; }
mkdir -p "$OUT_DIR" "$STATE_DIR"

emit() {
  local name=$1 sql=$2
  local mark_file="$STATE_DIR/$name"
  local mark rows
  mark="$(cat "$mark_file" 2>/dev/null || echo 0)"
  # not opened readonly, a hot journal needs replaying and only selects run here
  rows="$(sqlite3 -json "$DB" ".timeout 2000" "${sql//@MARK/$mark}")"
  if [[ -z "$rows" || "$rows" == "[]" ]]; then return 0; fi
  jq -c '.[]' <<<"$rows" >> "$OUT_DIR/dionaea.jsonl"
  jq -r 'max_by(.id) | .id' <<<"$rows" > "$mark_file"
  echo "$name $(jq 'length' <<<"$rows") new past $mark"
}

emit connections "
SELECT 'connections' AS tbl, c.connection AS id, c.connection_timestamp AS ts_epoch,
       c.connection_protocol, c.connection_transport, c.local_port,
       c.remote_host, c.remote_port
FROM connections c WHERE c.connection > @MARK ORDER BY c.connection"

emit logins "
SELECT 'logins' AS tbl, l.login AS id, c.connection_timestamp AS ts_epoch,
       c.connection_protocol, c.local_port, c.remote_host, c.remote_port,
       l.login_username, l.login_password
FROM logins l JOIN connections c ON c.connection = l.connection
WHERE l.login > @MARK ORDER BY l.login"

emit downloads "
SELECT 'downloads' AS tbl, d.download AS id, c.connection_timestamp AS ts_epoch,
       c.connection_protocol, c.local_port, c.remote_host, c.remote_port,
       d.download_url, d.download_md5_hash
FROM downloads d JOIN connections c ON c.connection = d.connection
WHERE d.download > @MARK ORDER BY d.download"
