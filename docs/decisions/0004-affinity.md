# 0004 session affinity

## context

- A source that lands on a different honeypot each connection sees a different machine each time
- Files vanish, shell history resets, the hostname changes, and the host key changes
- The redirect map is keyed by source address, so one source already maps to one honeypot while the row exists

## decision

- Affinity is the row. Nothing extra is needed to keep a source on its honeypot while it is registered
- A binding outlives the session. The reaper refuses a honeypot that any source is still bound to, even past the idle grace
- The window is separate from the grace. Grace is silence before a honeypot counts as idle, affinity is how long after that its attacker keeps it. Default five minutes against a one minute grace
- A live session refreshes the binding, so a long engagement never expires under its own attacker

## consequences

- An idle honeypot can sit for grace plus affinity before it is destroyed, which costs capacity under a wide attack
- If the bound honeypot dies, the row dies with it and the next connection lands somewhere else. Coherence breaks and the attacker can see it
- Detecting a container that died on its own is not handled. The row would point at a dead veth until the reaper or a restart cleared it
- Cowrie does not carry filesystem changes between sessions, so affinity gives the same machine and not the same state. The host key and hostname are consistent, a file the attacker wrote is not
