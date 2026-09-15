# verifier rejections

Four deliberate breaks, loaded with `bpftool prog load`. Read logs bottom up.

## no bounds check

Dropped the ethernet check, read `eth->h_proto`.

    invalid access to packet, off=13 size=1, R2(id=0,off=13,r=0)

`r` is bytes proven readable. Zero, so nothing can be read.

## check on the wrong header

Kept the ethernet check, dropped the IP one, read `ip->protocol`.

    invalid access to packet, off=23 size=1, R1(id=0,off=23,r=14)

Range 14, offset 23 needs 24. The comparison sets the range, so the check is the proof, not a guard.

## unbounded loop

`while (i < skb->len)`. Expected rejection, it loaded.

Termination is proved, not banned. Bounded loops allowed since 5.3, instruction budget is the backstop.

## map value, no NULL check

Dereferenced `bpf_map_lookup_elem` directly.

    R0 invalid mem access 'map_value_or_null'

Stays pointer-or-NULL until compared. Missing the check is a kernel NULL deref.

## bounding a packet value

IP header is variable length so the TCP offset comes from `ip->ihl * 4`. A 4 bit
field means the verifier knows only 0 to 60. Adding an unbounded value to a
packet pointer makes the result unprovable.

    if (ihl < sizeof(struct iphdr) || ihl > 60)
            return TC_ACT_OK;

Narrowing to 20 to 60 is what makes the next bounds check provable. A proof
obligation not a sanity check.

## note

Narrowing possible values is what earns access. Three of four caught.

No rejections after the deliberate breaks. Recognising the shapes was enough.
