-- table keyed by eventid, anything absent is a probe
local class_of = {
  ["cowrie.session.connect"] = "session.open",
  ["cowrie.session.closed"]  = "session.close",
  ["cowrie.login.failed"]    = "auth.attempt",
  ["cowrie.login.success"]   = "auth.attempt",
  ["cowrie.command.input"]   = "command.input",
  ["cowrie.command.failed"]  = "command.input",
}

-- fields the collector added, stripped so payload stays the original event
local added = { path = true, instance = true, honeypot = true }

function normalise(tag, ts, record)
  local payload = {}
  for k, v in pairs(record) do
    if not added[k] then payload[k] = v end
  end

  return 2, ts, {
    ts       = record.timestamp,
    instance = record.instance,
    honeypot = record.honeypot,
    session  = record.session,
    src_ip   = record.src_ip,
    src_port = record.src_port,
    dst_port = record.dst_port,
    class    = class_of[record.eventid] or "probe",
    payload  = payload,
  }
end
