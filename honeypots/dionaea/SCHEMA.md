# dionaea telemetry

Two outputs. `var/log/dionaea/dionaea.log` is unstructured C debug text, ~4200 lines per scan, unusable as evidence. The real store is `var/lib/dionaea/dionaea.sqlite`, 31 relational tables written by the log_sqlite handler.

`connections` is the spine, everything else joins to it by connection id.

| column | means |
|---|---|
| connection | primary key |
| connection_protocol | which emulated service handled it |
| connection_timestamp | unix epoch |
| connection_root, connection_parent | intended to link related connections, null in practice here |
| local_host, local_port | honeypot side |
| remote_host, remote_port | attacker side |

Protocol detail sits in per-service tables (`dcerpcrequests`, `mssql_commands`, `sip_commands`). Artefacts in `downloads`, credentials in `logins`, scanner OS guesses in `p0fs`.

## versus cowrie

Cowrie emits an ordered event stream keyed by session, read as a narrative of what an attacker typed. Dionaea records artefacts normalised across tables and joined by connection id. Neither converts to the other without inventing or discarding structure.

## fidelity

**It announces itself.** `nmap -sV -p 445` returns `microsoft-ds Dionaea honeypot smbd`.

**The emulation logs its own failures.** nmap probes produce `SMB did not get enough data` and `not really SMB` at critical level.

**Advertised services do not exist.** `ftp.yaml` is enabled but nothing binds port 21.

**SMB1 only and everything is anonymously writable.** `smb-protocols` returns `NT LM 0.12` alone, `smb-os-discovery` reports Windows XP, and ADMIN$, C$ and IPC$ all allow anonymous READ/WRITE. No supported release presents that combination.

## constraints

`log_json` crash-loops the container when enabled, so sqlite is the only structured source. `bistreams` is not created at runtime and must exist beforehand.

**Several enabled services cannot serve.** `http`, `tftp`, `ftp` and `printer` all log their root directory as not a directory at start, because those paths are absent from the bind mounted `var/lib`. They answer a connection and then do nothing, which a scanner sees as a service that negotiates and stalls.
