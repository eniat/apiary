# flapping as an attack surface

## the mechanism

- One threshold, load sitting on it, and the policy reverses almost every tick
- Measured over 30 ticks: 14 direction changes, 11 containers created and destroyed, and not one attacker connection reached any of them
- The load never changed character. It stayed near the threshold the whole time

## why this is not the usual autoscaler problem

- A web service's load is indifferent to the autoscaler. An attacker's load is not
- The thresholds are discoverable from outside. Send n flows, watch whether a new instance appears, adjust. A few minutes of probing finds the band
- Once found, parking just above it makes the defender build and destroy containers indefinitely for the cost of a few SYNs per tick
- The scaling signal is unserved malicious flows, which is the attacker's own traffic. Any autoscaler keyed on a signal the adversary writes is under adversarial control by construction

## what it costs the defender

- Create and destroy is the expensive operation. Twenty cold starts spanned 2.7 to 11.6 seconds of work each
- Container churn also disturbs honeypots already in service. 27 connections to a live decoy were refused across five create and destroy cycles, in clusters aligned to the churn, and none at all across 300 connections with the data plane detached. The cause is recorded as open in `docs/evaluation.md` rather than guessed at
- So the attack is not only resource exhaustion. It degrades coverage for every other attacker on the same bridge

## what was done

- A deadband between the up and down thresholds. 14 reversals fell to 3 on the same seeded load
- A minimum interval between actions, asymmetric because scaling up late loses an attacker and scaling down late only costs a container. 3 reversals fell to 0
- Containers created across the run fell from 11 to 4

## what is still true

- The band is still discoverable. Hysteresis raises the cost of finding it, it does not hide it
- The cooldown bounds the rate of damage rather than preventing it. An attacker can still force an action, just not faster than one per interval
- The real defence is that an action is now cheap. Promotion is a map write at roughly 9 microseconds against a container start at several seconds, so forcing one action every 30 seconds forces almost no work
- That is the argument for the warm pool restated adversarially. It was built to stop losing the connection that triggered a scale up, and it happens to be what makes this attack not worth mounting
