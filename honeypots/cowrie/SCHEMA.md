# cowrie telemetry

| eventid | means | key fields |
|---|---|---|
| cowrie.session.connect | new tcp session opened | session, src_ip, src_port, dst_port |
| cowrie.client.version | client ssh version string, sent pre-auth | version |
| cowrie.client.kex | key exchange algorithms the client offered | kexAlgs, keyAlgs, encCS |
| cowrie.login.failed | credential rejected | username, password |
| cowrie.login.success | credential accepted | username, password |
| cowrie.client.size | terminal dimensions requested | width, height |
| cowrie.client.var | environment variable sent by the client | name, value |
| cowrie.session.params | client architecture as cowrie infers it | arch |
| cowrie.command.input | command entered in the fake shell | input |
| cowrie.command.failed | command the emulation does not implement | input |
| cowrie.log.closed | tty recording written and closed | ttylog, shasum, duration_ms |
| cowrie.session.closed | session ended | duration_ms |

Every event carries `session` and `timestamp`. `session` is the join key for
reconstructing one attacker interaction.

`cowrie.session.file_download` does not appear. The emulated wget resolves the
host even when given a literal IPv4 address, which real wget does not, so the
fetch fails in a lab with no upstream resolver and the event is never produced.

## fidelity: how this honeypot can be detected

Each vector was tested against the running honeypot.

**Session PIDs decrease.** Two consecutive sessions gave shell PIDs 7666 then 6492. Linux allocates PIDs upward, so a later connection cannot hold a lower one.

**Uptime contradicts process start times.** `uptime` reports 11 minutes while every row in `ps aux` shows a START of Jul22, three weeks earlier.

**Unimplemented binaries fail distinctively.** `mount`, `dmesg` and `df` all return `cannot execute binary file: Exec format error`. Three core utilities failing that way does not happen on a real host.

**ps output is malformed.** VSZ and RSS are in bytes rather than kilobytes, giving systemd a 180 GB virtual size, and TIME reads `0.48` instead of `MM:SS`.

**Emulated wget resolves literal addresses.** `wget http://10.10.10.20/x` fails with a name resolution error for an address needing no resolution. Real wget skips DNS for a literal IPv4.

**Survives a version scan.** `nmap -sV -p 2222` reports OpenSSH 9.2p1 Debian 2+deb12u3, matching the configured banner, with no reference to Cowrie. The default banner would not have.
