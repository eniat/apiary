-- first word of the command
local by_cmd = {
  wget = "T1105", curl = "T1105", tftp = "T1105", scp = "T1105", ftpget = "T1105",
  uname = "T1082", hostname = "T1082", lscpu = "T1082", free = "T1082", df = "T1082", dmesg = "T1082",
  ls = "T1083", find = "T1083", pwd = "T1083",
  ps = "T1057", top = "T1057",
  ifconfig = "T1016", ip = "T1016", netstat = "T1016", ss = "T1016", route = "T1016", arp = "T1016",
  whoami = "T1033", id = "T1033", w = "T1033", who = "T1033", groups = "T1033",
  passwd = "T1098", useradd = "T1098", usermod = "T1098", adduser = "T1098",
  crontab = "T1053.003",
  chmod = "T1222.002",
  history = "T1070.003",
}

-- checked first, a substring anywhere in the command is enough
local by_text = {
  { "authorized_keys", "T1098.004" },
  { "HISTFILE", "T1070.003" },
  { "bash_history", "T1070.003" },
  { "/proc/cpuinfo", "T1082" },
  { "/etc/shadow", "T1003.008" },
  { "/etc/passwd", "T1087.001" },
}

local function technique(record)
  if record.class == "auth.attempt" then return "T1110" end
  if record.class == "file.transfer" then return "T1105" end
  if record.class ~= "command.input" then return nil end

  local input = record.payload and record.payload.input
  if type(input) ~= "string" then return nil end

  for _, p in ipairs(by_text) do
    if string.find(input, p[1], 1, true) then return p[2] end
  end
  local first = string.match(input, "^%s*(%S+)")
  if first == nil then return nil end
  -- a path in front of the binary is still that binary
  first = string.match(first, "([^/]+)$") or first
  return by_cmd[first]
end

function tag_attack(tag, ts, record)
  local t = technique(record)
  if t == nil then return 0, ts, record end
  record.technique = t
  return 2, ts, record
end
