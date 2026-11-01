-- table keyed by eventid, anything absent is a probe
local class_of = {
  ["cowrie.session.connect"] = "session.open",
  ["cowrie.session.closed"]  = "session.close",
  ["cowrie.login.failed"]    = "auth.attempt",
  ["cowrie.login.success"]   = "auth.attempt",
  ["cowrie.command.input"]   = "command.input",
  ["cowrie.command.failed"]  = "command.input",
}

-- dionaea has no event id, the source table is the signal
local class_of_table = {
  connections = "probe",
  logins      = "auth.attempt",
  downloads   = "file.transfer",
}

-- fields the collector added, stripped so payload stays the original event
local added = { path = true, instance = true, honeypot = true }

local function original(record)
  local payload = {}
  for k, v in pairs(record) do
    if not added[k] then payload[k] = v end
  end
  return payload
end

function normalise(tag, ts, record)
  return 2, ts, {
    ts       = record.timestamp,
    instance = record.instance,
    honeypot = record.honeypot,
    session  = record.session,
    src_ip   = record.src_ip,
    src_port = record.src_port,
    dst_port = record.dst_port,
    class    = class_of[record.eventid] or "probe",
    payload  = original(record),
  }
end

-- epoch seconds in, so the timestamp is returned as well as the record
function normalise_dionaea(tag, ts, record)
  local epoch = tonumber(record.ts_epoch) or 0
  return 1, epoch, {
    ts       = os.date("!%Y-%m-%dT%H:%M:%SZ", epoch),
    instance = record.instance,
    honeypot = record.honeypot,
    src_ip   = record.remote_host,
    src_port = record.remote_port,
    dst_port = record.local_port,
    class    = class_of_table[record.tbl] or "probe",
    payload  = original(record),
  }
end
