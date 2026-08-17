# common log schema

Cowrie is narrative: ordered events sharing a session id. 
Dionaea is artefact-centric: standalone connection rows in SQLite, no session concept. 
One shape over both is what lets a single query span them.

| field    | type              | notes                                 |
|----------|-------------------|---------------------------------------|
| ts       | RFC3339 UTC       | converted at ingest                   |
| instance | string            | container name now, instance id later |
| honeypot | cowrie \| dionaea | fixed per collector                   |
| session  | string or null    | cowrie only                           |
| src_ip   | string            |                                       |
| src_port | int               |                                       |
| dst_port | int               |                                       |
| class    | enum              | mapped from the native event          |
| payload  | object            | original event, unmodified            |

- class: session.open, session.close, auth.attempt, command.input, file.transfer, probe
- unmapped becomes probe, detail kept in payload
- adding a class is a schema change, adding a payload field is not

## cowrie

| eventid                     | class         |
|-----------------------------|---------------|
| cowrie.session.connect      | session.open  |
| cowrie.session.closed       | session.close |
| cowrie.login.failed/success | auth.attempt  |
| cowrie.command.input        | command.input |
| cowrie.command.failed       | command.input |
| everything else             | probe         |

## dionaea

| table       | class         |
|-------------|---------------|
| connections | probe         |
| logins      | auth.attempt  |
| downloads   | file.transfer |

- only these three hold attack data, the rest are static reference tables shipped with the image
- connections is probe not session.open: a completed record, not a lifecycle event, and session.open would imply a close that never arrives
- session is null: every connections row is its own root with a null parent, so correlation means grouping by src_ip over a window

## notes

- payload keeps the original verbatim so normalisation cannot lose what later matters
- src_ip and session are high cardinality: event body, never an index label
- Cowrie's log can contain undecodable lines, ingest counts and skips them rather than stopping
