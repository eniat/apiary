# moving a connection to a honeypot

## why the obvious thing fails

Both ends of a TCP connection hold state built during the handshake. Rewrite the destination mid connection and the honeypot gets a segment for a connection it never saw open, so its kernel sends a RST.

Tested rather than assumed. A connection was opened to one Cowrie, then a redirect row pointed the source at a second Cowrie listening on the same port. The next segment got a RST. The same probe without the redirect went through untouched. `../evidence/midflight-redirect.txt`

Same port rules out the boring explanation. Only the state was missing.

The RST also carried the honeypot's address, so the attacker's kernel dropped it and the connection hung to timeout. Done wrong this is not just a failed capture but a distinctive one.

## three options

- **Rewrite every packet from a flagged source.** No per connection state. Resets anything open at flag time, which is the failure above
- **Flag the source and act at the next SYN.** Neither end has state at a SYN so TCP never notices. Needs a flow table so later segments follow the SYN decision
- **Migrate the live connection.** Sequence translation and state injection into a kernel that never saw the handshake. Out of scope

## the choice

The second. Detection and steering come apart: flag on any signal, act at the next SYN, no timing agreement needed.

The cost is that anything before the flag goes unobserved. A scan caught on its tenth port sent nine elsewhere first. The flow table needs two entries per connection since only the forward packet carries the address the attacker dialled.

Next would be flagging on connection success rate rather than a port count. Threshold Random Walk classifies on fewer packets, which shrinks the window a source gets before anything notices.
