# 0003: redirect decided at connection setup

**Decision:** flag per source and redirect on the SYN. Connections open before the flag stay where they are.

**Why**
- A mid-stream redirect gets a RST as the honeypot has no state for the connection. Before and after in `docs/evidence/midflight-redirect.txt`
- At the SYN neither end has state so TCP never notices

**Cost**
- Anything a source did before the flag goes unseen
- Needs a flow table so later segments follow the SYN decision

**Current build**
- No return path so the RST never reaches the attacker and the connection hangs
- Once the flow table exists the same run should reach the original destination untouched. A RST then is a bug

**Rejected**
- Source match alone as the data plane does today: RSTs anything open at flag time
- Live connection migration: needs sequence translation and state injection
