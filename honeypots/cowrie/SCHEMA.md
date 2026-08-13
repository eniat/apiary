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
