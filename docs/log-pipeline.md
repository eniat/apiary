# log pipeline

## constraint

- a honeypot can live ninety seconds and be destroyed, so anything unshipped is gone
- attribution is stamped at capture time. the container does not exist at query time

## shape

| stage | what runs it | where |
|---|---|---|
| collect, enrich | fluent bit tail | defender host, one process |
| store | loki for lines, prometheus for numbers | containers, own bridge |
| query | grafana | container, own bridge |

- host collector not a sidecar. a sidecar doubles the container count this project exists to keep small
- log dirs are already bind mounted under /var/lib/apiary/logs/<instance>, so the honeypot image stays untouched
- monitoring is off apiary-net. a honeypot that gets out should not reach the evidence against it

## attribution

| field | source |
|---|---|
| instance | the tail path |
| honeypot | one tail stanza per type |
| session | the event body, cowrie only |

- instance from the path not cowrie's sensor. no sensor_name is set so the sensor is the docker hostname, while everything else names honeypots ap-hp-xxxxxxxx
- sqlite cant be tailed. dionaea needs a reader polling past a connection id watermark into json lines

## labels and content

every combination of label values is a stream, so labels stay bounded and anything attacker influenced goes in the body.

| field | where | why |
|---|---|---|
| job | label | one value |
| honeypot | label | two values |
| class | label | six, fixed by the schema. twelve streams is the ceiling |
| instance | content | new value per create |
| session | content | one per connection |
| src_ip, src_port | content | unbounded, attacker chosen |
| dst_port | content | nothing queries on it alone |
| payload | content | never indexed |

- a label an attacker can mint is a denial of service on your own index
- instance stays queryable as a filter once a stream is selected

## retention and loss

- loki keeps fourteen days, matching the rotated cowrie json
- the archive is the record, loki a query layer over a copy. archive before destroy stays because continuous shipping is best effort
- fluent bit buffers to the filesystem and pauses the input at its limit rather than discarding. the files are still on the host
- log root and archive grow without bound and need the same prune

## clock

- one clock, every producer is on the defender. cowrie is UTC already
- ingest time never goes in a correlated field

## reaching it

- loki and grafana bind 127.0.0.1, nothing on the lab segment for the attacker to find
- ssh -L 3000:127.0.0.1:3000 apiary@10.10.10.10
