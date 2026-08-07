description = [[
vulnlocal correlates Nmap -sV service/version data against an offline
vulnlocal.pack index (plain TSV buckets readable by Lua with no external
tools) — or against the live vulnlocal HTTP API.

Modes:
  Online API (app must be running; http or https):
    --script-args vulnlocal.api=http://127.0.0.1:8088
    --script-args vulnlocal.api=https://127.0.0.1:8443
    --script-args vulnlocal.api=127.0.0.1:8088
      (no scheme → try http then https)

  Offline pack (pure Lua, no sqlite3 CLI):
    --script-args vulnlocal.db=D:/path/to/vulnlocal.pack

If both are set, the API is tried first; the pack is used when the API
is unreachable. If the pack path is omitted, the script tries
nmap.fetchfile("scripts/vulnlocal/db/vulnlocal.pack/META").

Matching:
  - Nmap -sV product/version plus banner side-products (e.g. Python inside Werkzeug)
  - NVD cpeMatch version ranges (versionStart/End) plus concrete CPE versions
  - Pre-release CPE updates (alpha/beta/rc) ignored for GA detections
  - Output grouped by CPE with CVE id, CVSS score, and cve.org link

Advisory correlation only — does not verify or exploit flaws.
]]

---
-- @usage
-- nmap -sV --script vulnlocal/vulnlocal --script-args vulnlocal.api=http://127.0.0.1:8088 <target>
-- nmap -sV --script vulnlocal/vulnlocal --script-args vulnlocal.api=https://127.0.0.1:8443 <target>
-- nmap -sV --script vulnlocal/vulnlocal --script-args "vulnlocal.db=D:/path/to/vulnlocal.pack" <target>
--
-- @args vulnlocal.api Base URL of the running vulnlocal app (http:// or https://).
-- @args vulnlocal.db Path to offline vulnlocal.pack directory (or its META file).
--
-- @output
-- 8088/tcp open  http Werkzeug httpd 3.1.6 (Python 3.14.0)
-- | vulnlocal:
-- |   cpe:/a:python:python:3.14.0:
-- |       CVE-2026-7210   7.5     https://www.cve.org/CVERecord?id=CVE-2026-7210
-- |_      CVE-2025-13836  7.5     https://www.cve.org/CVERecord?id=CVE-2025-13836
--

author = "vulnlocal project"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "vuln", "discovery"}

local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local have_stringaux, stringaux = pcall(require, "stringaux")
local strsplit = (have_stringaux and stringaux or stdnse).strsplit
local have_http, http = pcall(require, "http")
local have_json, json = pcall(require, "json")
local have_url, url = pcall(require, "url")

local DB_ARG = stdnse.get_script_args("vulnlocal.db")
local API_ARG = stdnse.get_script_args("vulnlocal.api")
local MAX_RESULTS = 50
local IS_WINDOWS = package.config:sub(1, 1) == "\\"

local NOISE = {
  httpd=true, smtpd=true, ftpd=true, daemon=true, server=true,
  service=true, protocol=true, open=true, the=true, ["and"]=true,
}

local WILDCARD_VER = {
  [""]=true, ["*"]=true, ["-"]=true, ["n/a"]=true, ["na"]=true,
  ["any"]=true, ["unspecified"]=true, ["unknown"]=true,
}

portrule = function(host, port)
  if not port.version then
    return false
  end
  local has_ver = port.version.version and port.version.version ~= ""
  return has_ver
end

-- Noisy fingerprints that flood CVE hits without being useful (skip entirely).
local function is_suppressed_fingerprint(product, version)
  local p = string.lower(product or "")
  local v = string.lower(version or "")
  -- Microsoft HTTPAPI httpd 2.0 — very common Windows banner, noisy CVE noise
  if string.find(p, "httpapi", 1, true)
      and (string.find(p, "microsoft", 1, true) or string.find(p, "httpd", 1, true)) then
    if v == "" or v == "2.0" or string.match(v, "^2%.0") then
      return true
    end
  end
  return false
end

local function normalize_db_path(p)
  if not p or p == "" then
    return p
  end
  -- Nmap script-args use \-escapes (\v \t \n). Restore path letters, then unify separators.
  p = string.gsub(p, "\v", "v")
  p = string.gsub(p, "\t", "t")
  p = string.gsub(p, "\n", "n")
  p = string.gsub(p, "\r", "r")
  p = string.gsub(p, "\\", "/")
  return p
end

local function file_exists(path)
  if not path or path == "" then
    return false
  end
  local f = io.open(path, "rb")
  if not f then
    return false
  end
  f:close()
  return true
end

local function is_pack_root(path)
  if not path or path == "" then
    return false
  end
  return file_exists(path .. "/META") or file_exists(path .. "\\META")
end

--- Resolve offline vulnlocal.pack directory (plain TSV; no external CLI).
local function resolve_pack()
  local candidates = {}
  local function add(p)
    if p and p ~= "" then
      candidates[#candidates + 1] = p
      local n = normalize_db_path(p)
      if n ~= p then
        candidates[#candidates + 1] = n
      end
    end
  end

  if DB_ARG and DB_ARG ~= "" then
    add(DB_ARG)
    -- Allow pointing at META file or legacy .db next to .pack
    local p = normalize_db_path(DB_ARG)
    local pl = string.lower(p)
    if string.match(pl, "meta$") then
      add(string.gsub(p, "[/\\][Mm][Ee][Tt][Aa]$", ""))
    end
    if string.sub(pl, -3) == ".db" then
      add(string.gsub(p, "[Dd][Bb]$", "pack"))
      local dir = string.match(p, "^(.*)[/\\][^/\\]+$")
      if dir then
        add(dir .. "/vulnlocal.pack")
      end
    end
  end

  local fetched = nmap.fetchfile("scripts/vulnlocal/db/vulnlocal.pack/META")
  if fetched then
    add(string.gsub(fetched, "[/\\]META$", ""))
  end
  fetched = nmap.fetchfile("scripts/vulnlocal/db/vulnlocal.pack")
  if fetched then
    add(fetched)
  end

  for _, path in ipairs(candidates) do
    if is_pack_root(path) then
      return path
    end
    -- If user passed META path that exists as a file, parent is pack root.
    if file_exists(path) and string.match(normalize_db_path(path), "META$") then
      local parent = string.match(normalize_db_path(path), "^(.*)[/\\]META$")
      if parent and is_pack_root(parent) then
        return parent
      end
    end
  end
  if DB_ARG and DB_ARG ~= "" then
    stdnse.debug1("vulnlocal: pack not found for vulnlocal.db=%s", DB_ARG)
  end
  return nil
end

-- Compatibility alias used by action()
local function resolve_db()
  return resolve_pack()
end

local function lower(s)
  return string.lower(s or "")
end

--- 8-bit bucket — must match Python pack_bucket().
local function bucket8(key)
  local h = 0
  local s = lower(key)
  for i = 1, #s do
    h = ((h * 31) + string.byte(s, i)) % 256
  end
  return string.format("%02x", h)
end

local function pack_join(pack_root, ...)
  local parts = { normalize_db_path(pack_root) }
  for i = 1, select("#", ...) do
    parts[#parts + 1] = select(i, ...)
  end
  return table.concat(parts, "/")
end

local function iter_tsv(path, fn)
  local f = io.open(path, "rb")
  if not f then
    return
  end
  for line in f:lines() do
    if line and line ~= "" then
      fn(strsplit("\t", line))
    end
  end
  f:close()
end

local function tokenize_product(prod)
  local cleaned = string.gsub(lower(prod), "[^%w%.%-%+_]+", " ")
  cleaned = string.gsub(cleaned, "%s+", " ")
  local out = {}
  for token in string.gmatch(cleaned, "%S+") do
    if #token >= 3 and not NOISE[token] then
      out[#out + 1] = token
    end
  end
  return out
end

local function norm_ver(ver)
  local v = lower(string.gsub(ver or "", "^%s+", ""))
  v = string.gsub(v, "%s+$", "")
  if #v > 1 and string.sub(v, 1, 1) == "v" and string.match(string.sub(v, 2, 2), "%d") then
    v = string.sub(v, 2)
  end
  return v
end

--- Concrete version alignment only. Bare CPE '*' / '-' never match.
local function version_matches(detected, dbver)
  local d = norm_ver(detected)
  local b = norm_ver(dbver)
  if d == "" then
    return false
  end
  if WILDCARD_VER[b] then
    return false
  end
  if d == b then
    return true
  end
  local function boundary_prefix(longer, shorter)
    if string.sub(longer, 1, #shorter) ~= shorter then
      return false
    end
    if #longer == #shorter then
      return true
    end
    local nxt = string.sub(longer, #shorter + 1, #shorter + 1)
    return not string.match(nxt, "%d")
  end
  return boundary_prefix(d, b) or boundary_prefix(b, d)
end

local function version_sql_needles(ver)
  local v = norm_ver(ver)
  if v == "" then
    return {}
  end
  local out = { ":" .. v .. ":" }
  local parts = {}
  for p in string.gmatch(v, "[^.]+") do
    parts[#parts + 1] = p
  end
  if #parts >= 2 then
    local mm = parts[1] .. "." .. parts[2]
    local needle = ":" .. mm .. ":"
    if needle ~= out[1] then
      out[#out + 1] = needle
    end
  end
  return out
end

--- Parse CPE 2.3 or legacy cpe:/… → vendor/product/version + soft prefix.
local function parse_cpe(cpe)
  local raw = lower(cpe or "")
  if raw == "" then
    return nil
  end
  if string.sub(raw, 1, 5) == "cpe:/" then
    local body = string.sub(raw, 6)
    local parts = strsplit(":", body)
    if #parts < 3 then
      return nil
    end
    return {
      part = parts[1],
      vendor = parts[2] or "",
      product = parts[3] or "",
      version = parts[4] or "",
      update = parts[5] or "",
      soft = string.format("cpe:2.3:%s:%s:%s", parts[1], parts[2] or "", parts[3] or ""),
    }
  end
  raw = string.gsub(raw, "^cpe:/", "cpe:2.3:")
  local parts = strsplit(":", raw)
  -- cpe : 2.3 : part : vendor : product : version : update
  if #parts < 5 or parts[1] ~= "cpe" or parts[2] ~= "2.3" then
    return nil
  end
  return {
    part = parts[3],
    vendor = parts[4] or "",
    product = parts[5] or "",
    version = parts[6] or "",
    update = parts[7] or "",
    soft = string.format("cpe:2.3:%s:%s:%s", parts[3], parts[4] or "", parts[5] or ""),
  }
end

local function cpe_update_matches_detected(detected, update)
  local u = norm_ver(update)
  if WILDCARD_VER[u] then
    return true
  end
  local d = norm_ver(detected)
  if u ~= "" and string.find(d, u, 1, true) then
    return true
  end
  if string.match(lower(u), "^(alpha|beta|rc|preview|pre|dev|snapshot)[%.%_%-]?%d*$") then
    return false
  end
  return true
end

local function cpe_uri_ok_for_detected(detected, cpe)
  -- Reject pre-release tags embedded in the CPE URI (e.g. ...:3.14.0:alpha1:...).
  local raw = lower(cpe or "")
  if string.find(raw, ":alpha", 1, true) or string.find(raw, ":beta", 1, true)
      or string.find(raw, ":rc", 1, true) or string.find(raw, ":preview", 1, true) then
    local d = norm_ver(detected)
    if not (string.find(d, "alpha", 1, true) or string.find(d, "beta", 1, true)
        or string.find(d, "rc", 1, true)) then
      return false
    end
  end
  return true
end

local function product_name_matches(tokens, vendor, product)
  if not tokens or #tokens == 0 or not product or product == "" then
    return false
  end
  local prod = lower(product)
  local vend = lower(vendor or "")
  local hit = false
  for _, tok in ipairs(tokens) do
    if prod == tok or string.find(prod, tok, 1, true) then
      hit = true
      break
    end
  end
  if hit then
    return true
  end
  local blob = vend .. " " .. prod
  local n = math.min(#tokens, 3)
  for i = 1, n do
    if not string.find(blob, tokens[i], 1, true) then
      return false
    end
  end
  return n > 0
end

local function cve_link(id)
  return "https://www.cve.org/CVERecord?id=" .. id
end

local function parse_score(raw)
  return tonumber(raw) or 0
end

local function push_hit(bucket, key, rec)
  if bucket[key] then
    if (rec.score or 0) > (bucket[key].score or 0) then
      bucket[key] = rec
    end
    return
  end
  bucket[key] = rec
end

local function bucket_to_sorted(bucket)
  local list = {}
  for _, rec in pairs(bucket) do
    list[#list + 1] = rec
  end
  table.sort(list, function(a, b)
    if a.score == b.score then
      return tostring(a.id) > tostring(b.id)
    end
    return a.score > b.score
  end)
  if #list > MAX_RESULTS then
    local clipped = {}
    for i = 1, MAX_RESULTS do
      clipped[i] = list[i]
    end
    return clipped
  end
  return list
end

local function ver_pad(ver)
  local v = norm_ver(ver)
  if v == "" or WILDCARD_VER[v] then
    return nil
  end
  v = string.gsub(v, "[_%-]", ".")
  local parts = {}
  for p in string.gmatch(v, "[^.]+") do
    local num = tonumber(p)
    if num then
      parts[#parts + 1] = string.format("%08d", num)
    else
      local tag, n = string.match(lower(p), "^(alpha|beta|rc|preview|pre|dev|a|b)(%d*)$")
      if tag then
        local rank = ({ a = 1, alpha = 1, b = 2, beta = 2, pre = 3, preview = 3, rc = 4, dev = 0 })[tag] or 5
        parts[#parts + 1] = string.format("pre%02d%04d", rank, tonumber(n) or 0)
      else
        parts[#parts + 1] = "x" .. lower(p)
      end
    end
  end
  return table.concat(parts, ".")
end

local function ver_cmp(a, b)
  local pa, pb = ver_pad(a), ver_pad(b)
  if not pa or not pb then
    return 0
  end
  if pa < pb then return -1 end
  if pa > pb then return 1 end
  return 0
end

local function version_in_nvd_range(detected, si, sx, ei, ex)
  if ver_pad(detected) == nil then
    return false
  end
  if si and si ~= "" and not WILDCARD_VER[norm_ver(si)] and ver_cmp(detected, si) < 0 then
    return false
  end
  if sx and sx ~= "" and not WILDCARD_VER[norm_ver(sx)] and ver_cmp(detected, sx) <= 0 then
    return false
  end
  if ei and ei ~= "" and not WILDCARD_VER[norm_ver(ei)] and ver_cmp(detected, ei) > 0 then
    return false
  end
  if ex and ex ~= "" and not WILDCARD_VER[norm_ver(ex)] and ver_cmp(detected, ex) >= 0 then
    return false
  end
  return true
end

local function match_applies_to_version(detected, cpe_version, cpe_update, si, sx, ei, ex)
  local ranged = (si and si ~= "" and not WILDCARD_VER[norm_ver(si)])
      or (sx and sx ~= "" and not WILDCARD_VER[norm_ver(sx)])
      or (ei and ei ~= "" and not WILDCARD_VER[norm_ver(ei)])
      or (ex and ex ~= "" and not WILDCARD_VER[norm_ver(ex)])
  local cver = norm_ver(cpe_version or "")
  if ranged then
    if not version_in_nvd_range(detected, si, sx, ei, ex) then
      return false, ""
    end
    if cver ~= "" and not WILDCARD_VER[cver] and not version_matches(detected, cver) then
      return false, ""
    end
    if not cpe_update_matches_detected(detected, cpe_update or "") then
      return false, ""
    end
    if cver ~= "" and not WILDCARD_VER[cver] then
      return true, cver
    end
    return true, norm_ver(detected)
  end
  if cver ~= "" and not WILDCARD_VER[cver] then
    if version_matches(detected, cver) and cpe_update_matches_detected(detected, cpe_update or "") then
      return true, cver
    end
    return false, ""
  end
  return false, ""
end

local function soft_aliases(soft)
  local out = { soft }
  local reps = {
    {":python:python", ":python:cpython"},
    {":python:cpython", ":python:python"},
    {":nginx:nginx", ":f5:nginx"},
    {":f5:nginx", ":nginx:nginx"},
    {":apache:httpd", ":apache:http_server"},
    {":apache:http_server", ":apache:httpd"},
    {":nodejs:nodejs", ":nodejs:node.js"},
    {":nodejs:node.js", ":nodejs:nodejs"},
  }
  for _, pair in ipairs(reps) do
    if string.find(soft, pair[1], 1, true) then
      out[#out + 1] = string.gsub(soft, pair[1], pair[2], 1)
    end
  end
  return out
end

local function match_by_ranges(pack_root, cpes, detected_version)
  local hits = {}
  if not pack_root or not cpes or #cpes == 0 or not detected_version or detected_version == "" then
    return hits
  end
  local seen_soft = {}
  for _, cpe in ipairs(cpes) do
    local parsed = parse_cpe(cpe)
    local soft = parsed and parsed.soft or nil
    if not soft then
      local needle = string.gsub(lower(cpe), "^cpe:/", "cpe:2.3:")
      soft = string.match(needle, "^(cpe:2%.3:[aho]:[^:]+:[^:]+)") or needle
    end
    for _, s in ipairs(soft_aliases(soft)) do
      local skey = lower(s)
      if not seen_soft[skey] then
        seen_soft[skey] = true
        local path = pack_join(pack_root, "matches", bucket8(skey) .. ".tsv")
        iter_tsv(path, function(cols)
          -- soft,cve_id,cpe,version,update,si,sx,ei,ex,vulnerable,score,title
          if lower(cols[1] or "") ~= skey then
            return
          end
          local vuln = tonumber(cols[10]) or 1
          if vuln == 0 then
            return
          end
          local id = cols[2]
          local ok, matched = match_applies_to_version(
            detected_version, cols[4], cols[5], cols[6], cols[7], cols[8], cols[9]
          )
          if id and ok and cpe_uri_ok_for_detected(detected_version, cols[3] or "") then
            local how = "cpe"
            if (cols[6] and cols[6] ~= "") or (cols[7] and cols[7] ~= "")
                or (cols[8] and cols[8] ~= "") or (cols[9] and cols[9] ~= "") then
              how = "cpe_range"
            end
            push_hit(hits, id, {
              id = id,
              score = parse_score(cols[11]),
              title = cols[12] or "",
              how = how,
              matched_version = matched,
              link = cve_link(id),
            })
          end
        end)
      end
    end
  end
  return hits
end

local function foreach_match_for_soft(pack_root, soft, fn)
  local skey = lower(soft)
  local path = pack_join(pack_root, "matches", bucket8(skey) .. ".tsv")
  iter_tsv(path, function(cols)
    if lower(cols[1] or "") == skey then
      fn(cols)
    end
  end)
end

local function product_hit_has_ga_cpe(pack_root, cve_id, vendor, product, detected_ver)
  local soft = string.format("cpe:2.3:a:%s:%s", lower(vendor or ""), lower(product or ""))
  local saw = false
  local ok_hit = false
  foreach_match_for_soft(pack_root, soft, function(cols)
    if cols[2] ~= cve_id then
      return
    end
    saw = true
    local vuln = tonumber(cols[10]) or 1
    if vuln == 0 then
      return
    end
    local ok = match_applies_to_version(
      detected_ver, cols[4], cols[5], cols[6], cols[7], cols[8], cols[9]
    )
    if ok and cpe_uri_ok_for_detected(detected_ver, cols[3] or "") then
      ok_hit = true
    end
  end)
  if saw then
    return ok_hit
  end
  return true
end

local function match_by_products(pack_root, product, version)
  local hits = {}
  local tokens = tokenize_product(product or "")
  if #tokens == 0 or not version or version == "" or not pack_root then
    return hits
  end
  table.sort(tokens, function(a, b) return #a > #b end)
  local primary = tokens[1]
  local ver_norm = norm_ver(version)
  local path = pack_join(pack_root, "products", bucket8(primary) .. ".tsv")
  local n = 0
  iter_tsv(path, function(cols)
    -- product_key,vendor,product,version,cve_id,score,title
    if n >= 800 then
      return
    end
    local pkey = lower(cols[1] or "")
    if not string.find(pkey, primary, 1, true) then
      return
    end
    local vendor = cols[2] or ""
    local prod = cols[3] or ""
    local ver = cols[4] or ""
    local id = cols[5]
    local ver_l = lower(ver)
    if ver_l ~= ver_norm and string.sub(ver_l, 1, #ver_norm) ~= ver_norm then
      return
    end
    if id and product_name_matches(tokens, vendor, prod) and version_matches(version, ver)
        and product_hit_has_ga_cpe(pack_root, id, vendor, prod, version) then
      n = n + 1
      push_hit(hits, id, {
        id = id,
        score = parse_score(cols[6]),
        title = cols[7] or "",
        how = "product",
        matched_version = ver,
        link = cve_link(id),
      })
    end
  end)
  return hits
end

local function synth_cpe(product, version)
  local raw = lower(product or "")
  raw = string.gsub(raw, "%f[%w]httpd%f[%W]", " ")
  raw = string.gsub(raw, "[^%w%.%+%-%_]+", " ")
  raw = string.gsub(raw, "^%s+", "")
  local prod = string.match(raw, "%S+") or "unknown"
  local vendor = prod
  local aliases = {
    python = {"python", "python"},
    cpython = {"python", "python"},
    openssl = {"openssl", "openssl"},
    openssh = {"openbsd", "openssh"},
    nginx = {"f5", "nginx"},
    apache = {"apache", "http_server"},
    httpd = {"apache", "http_server"},
    postgresql = {"postgresql", "postgresql"},
    postgres = {"postgresql", "postgresql"},
    redis = {"redis", "redis"},
    nodejs = {"nodejs", "node.js"},
    node = {"nodejs", "node.js"},
    werkzeug = {"palletsprojects", "werkzeug"},
  }
  if aliases[prod] then
    vendor, prod = aliases[prod][1], aliases[prod][2]
  end
  local ver = norm_ver(version)
  if ver == "" then ver = "*" end
  return string.format("cpe:/a:%s:%s:%s", vendor, prod, ver)
end

local function cpe_belongs_to_product(cpe, product)
  local parsed = parse_cpe(cpe)
  if not parsed or not parsed.product or parsed.product == "" then
    return false
  end
  local tokens = tokenize_product(product or "")
  if #tokens == 0 then
    return false
  end
  local cpe_prod = lower(parsed.product)
  local cpe_vend = lower(parsed.vendor or "")
  local aliases = {
    python = { python = true, cpython = true },
    cpython = { python = true, cpython = true },
    werkzeug = { werkzeug = true },
  }
  table.sort(tokens, function(a, b) return #a > #b end)
  local primary = tokens[1]
  local family = aliases[primary]
  if family and family[cpe_prod] then
    return true
  end
  for _, t in ipairs(tokens) do
    if cpe_prod == t or string.find(cpe_prod, t, 1, true) then
      return true
    end
  end
  local blob = cpe_vend .. " " .. cpe_prod
  for _, t in ipairs(tokens) do
    if string.find(blob, t, 1, true) then
      return true
    end
  end
  return false
end

local function discover_targets(product, version, cpes, extrainfo)
  local out = {}
  local seen = {}
  local function add(prod, ver, extra_cpes)
    prod = tostring(prod or "")
    ver = tostring(ver or "")
    if prod == "" or ver == "" then return end
    local key = lower(prod) .. "|" .. norm_ver(ver)
    if seen[key] then return end
    seen[key] = true
    local list = {}
    for _, c in ipairs(extra_cpes or {}) do
      if cpe_belongs_to_product(c, prod) then
        list[#list + 1] = c
      end
    end
    local synth = synth_cpe(prod, ver)
    local has = false
    for _, c in ipairs(list) do if c == synth then has = true break end end
    if not has then table.insert(list, 1, synth) end
    out[#out + 1] = { product = prod, version = ver, cpes = list }
  end
  local cpe_list = {}
  if type(cpes) == "table" then
    for _, c in ipairs(cpes) do cpe_list[#cpe_list + 1] = c end
  elseif type(cpes) == "string" and cpes ~= "" then
    cpe_list[1] = cpes
  end
  add(product, version, cpe_list)
  local blob = (product or "") .. " " .. (extrainfo or "")
  for prod, ver in string.gmatch(blob, "%(%s*([%a][%w%.%+%-%_]*)%s+(v?%d[%w%.%+%-%_]*)%s*%)") do
    add(prod, ver, {})
  end
  for prod, ver in string.gmatch(blob, "([Pp]ython)%s+(v?%d[%w%.%+%-%_]*)") do
    add(prod, ver, {})
  end
  -- Side targets from Nmap CPEs (e.g. cpe:/a:python:python:3.14.0 on Werkzeug)
  for _, cpe in ipairs(cpe_list) do
    local parsed = parse_cpe(cpe)
    if parsed and parsed.product and parsed.product ~= ""
        and parsed.version and parsed.version ~= ""
        and not WILDCARD_VER[norm_ver(parsed.version)] then
      add(parsed.product, parsed.version, { cpe })
    end
  end
  return out
end

local function format_hit_line(r)
  local score = string.format("%.1f", r.score or 0)
  return string.format("\t%s\t%s\thttps://www.cve.org/CVERecord?id=%s", tostring(r.id or ""), score, tostring(r.id or ""))
end

local function format_vulners_style(by_cpe)
  if not by_cpe or #by_cpe == 0 then
    return nil
  end
  local lines = {}
  for _, group in ipairs(by_cpe) do
    lines[#lines + 1] = "  " .. tostring(group.cpe or "cpe:/a:unknown:unknown") .. ":"
    for _, r in ipairs(group.cves or {}) do
      lines[#lines + 1] = format_hit_line(r)
    end
  end
  return table.concat(lines, "\n")
end

local function merge_hits_by_cpe(groups)
  -- groups: list of {cpe=uri, hits=bucket}
  local by_cpe = {}
  local order = {}
  for _, g in ipairs(groups) do
    local uri = g.cpe or "cpe:/a:unknown:unknown"
    if not by_cpe[uri] then
      by_cpe[uri] = {}
      order[#order + 1] = uri
    end
    for id, rec in pairs(g.hits or {}) do
      push_hit(by_cpe[uri], id, rec)
    end
  end
  local out = {}
  for _, uri in ipairs(order) do
    local rows = bucket_to_sorted(by_cpe[uri])
    if #rows > 0 then
      out[#out + 1] = { cpe = uri, cves = rows }
    end
  end
  return out
end

local function url_encode(s)
  s = tostring(s or "")
  if have_url and url and url.escape then
    return url.escape(s)
  end
  return (string.gsub(s, "([^%w%-_%.%~])", function(c)
    return string.format("%%%02X", string.byte(c))
  end))
end

local function shell_quote(path)
  return '"' .. string.gsub(path or "", '"', '') .. '"'
end

local function normalize_api_base(base)
  base = string.gsub(base or "", "%s+", "")
  base = string.gsub(base, "/+$", "")
  return base
end

--- Build candidate API bases: honor explicit http/https; otherwise try both.
local function api_base_candidates(base)
  base = normalize_api_base(base)
  if base == "" then
    return {}
  end
  if string.find(base, "^https://") or string.find(base, "^http://") then
    return { base }
  end
  -- Bare host[:port] → probe plaintext first, then TLS (self-signed OK via curl -k).
  return { "http://" .. base, "https://" .. base }
end

local function parse_api_host(base)
  local scheme, host, port, path = string.match(base, "^(https?)://([^:/]+):?(%d*)(.*)$")
  if not host then
    -- IPv6 literal: https://[::1]:8443
    scheme, host, port, path = string.match(base, "^(https?)://%[([^%]]+)%]:?(%d*)(.*)$")
  end
  if not host then
    return nil
  end
  port = tonumber(port)
  if not port then
    port = (scheme == "https") and 443 or 80
  end
  if not path or path == "" then
    path = "/"
  end
  return scheme, host, port, path
end

local function api_rows_from_json(list)
  local out = {}
  if type(list) ~= "table" then
    return out
  end
  for _, item in ipairs(list) do
    if type(item) == "table" and item.id then
      out[#out + 1] = {
        id = tostring(item.id),
        score = tonumber(item.score) or 0,
        title = tostring(item.title or ""),
        how = tostring(item.how or ""),
        matched_version = tostring(item.matched_version or ""),
        link = tostring(item.link or ""),
      }
    end
  end
  return out
end

local function http_ok(status)
  return tonumber(status) == 200
end

-- Nmap json.parse returns (status, value). Do not wrap with pcall in a way that
-- discards the second return value.
local function parse_api_json(body)
  if not body or body == "" then
    return nil, "empty body"
  end
  if have_json and json and json.parse then
    local status, parsed = json.parse(body)
    if status and type(parsed) == "table" then
      return parsed, nil
    end
    if type(status) == "table" then
      -- Defensive: some environments may return the table first.
      return status, nil
    end
    return nil, tostring(parsed or status or "json parse failed")
  end
  return nil, "json library unavailable"
end

local function api_fetch_once(api_base, path)
  local full_url = api_base .. path
  local body, status = nil, nil
  local scheme, host, port = parse_api_host(api_base)

  if have_http and http and host then
    local opts = {
      timeout = 8000,
      header = { ["Accept"] = "application/json" },
      any_af = true,
      scheme = scheme, -- "http" or "https" — forces SSL when https
    }
    local resp
    if http.get_url then
      resp = http.get_url(full_url, opts)
    else
      resp = http.get(host, port, path, opts)
    end
    if resp then
      status = resp.status
      body = resp.body
      stdnse.debug1(
        "vulnlocal: API %s status=%s body_len=%s",
        tostring(scheme),
        tostring(status),
        tostring(body and #body or 0)
      )
    end
  end

  -- Fallback: curl (localhost / self-signed TLS via -k)
  if not body or body == "" or not http_ok(status) then
    local redirect = IS_WINDOWS and " 2>nul" or " 2>/dev/null"
    local insecure = (scheme == "https") and "-k " or ""
    local cmd = string.format(
      'curl -sS -m 8 %s-H "Accept: application/json" %s%s',
      insecure,
      shell_quote(full_url),
      redirect
    )
    local fh = io.popen(cmd)
    if fh then
      local curl_body = fh:read("*a") or ""
      fh:close()
      if curl_body ~= "" and (string.find(curl_body, '"source"%s*:') or string.find(curl_body, '"by_cpe"')
          or string.find(curl_body, '"product_match"')) then
        body = curl_body
        status = 200
        stdnse.debug1("vulnlocal: API curl fallback (%s) ok body_len=%s", tostring(scheme), tostring(#body))
      end
    end
  end

  return body, status, full_url
end

local function correlate_via_api(api_base, product, version, cpes, extrainfo)
  local candidates = api_base_candidates(api_base)
  if #candidates == 0 then
    return nil, "empty api base"
  end

  local q = {
    "product=" .. url_encode(product or ""),
    "version=" .. url_encode(version or ""),
    "extrainfo=" .. url_encode(extrainfo or ""),
    "limit=" .. tostring(MAX_RESULTS),
  }
  for _, cpe in ipairs(cpes or {}) do
    q[#q + 1] = "cpe=" .. url_encode(cpe)
  end
  local query = table.concat(q, "&")
  local path = "/api/nse/correlate?" .. query

  local body, status, used_base, last_err = nil, nil, nil, nil
  for _, base in ipairs(candidates) do
    local b, st = api_fetch_once(base, path)
    if b and b ~= "" and http_ok(st) then
      body, status, used_base = b, st, base
      break
    end
    last_err = string.format("%s -> http %s", base, tostring(st or "fail"))
  end

  if not body or body == "" or not http_ok(status) then
    return nil, last_err or "api http fail"
  end

  local payload, perr = parse_api_json(body)
  if not payload then
    return nil, "json parse failed: " .. tostring(perr or "")
  end

  return {
    cpe = api_rows_from_json(payload.cpe),
    product_match = api_rows_from_json(payload.product_match),
    by_cpe = payload.by_cpe or {},
    keyword = {},
    exploitdb = {},
    source = "api:" .. used_base,
    match_mode = "cpe_nvd_ranges",
  }, nil
end

local function correlate_via_db(pack_root, product, version, cpes, extrainfo)
  if not pack_root then
    return nil, "no pack"
  end
  if not is_pack_root(pack_root) then
    return nil, "invalid pack (missing META)"
  end
  local targets = discover_targets(product, version, cpes, extrainfo)
  local groups = {}
  for _, t in ipairs(targets) do
    local range_bucket = match_by_ranges(pack_root, t.cpes, t.version)
    local prod_bucket = match_by_products(pack_root, t.product, t.version)
    local merged = {}
    for id, rec in pairs(range_bucket) do push_hit(merged, id, rec) end
    for id, rec in pairs(prod_bucket) do push_hit(merged, id, rec) end
    groups[#groups + 1] = { cpe = synth_cpe(t.product, t.version), hits = merged }
  end
  local by_cpe = merge_hits_by_cpe(groups)
  local flat = {}
  for _, g in ipairs(by_cpe) do
    for _, r in ipairs(g.cves or {}) do
      flat[#flat + 1] = r
    end
  end
  table.sort(flat, function(a, b)
    if a.score == b.score then return tostring(a.id) > tostring(b.id) end
    return a.score > b.score
  end)
  return {
    cpe = flat,
    product_match = {},
    by_cpe = by_cpe,
    keyword = {},
    exploitdb = {},
    source = "pack:" .. pack_root,
    match_mode = "cpe_nvd_ranges",
  }, nil
end

local function result_has_hits(result)
  if not result then
    return false
  end
  if type(result.by_cpe) == "table" then
    for _, g in ipairs(result.by_cpe) do
      if type(g.cves) == "table" and #g.cves > 0 then
        return true
      end
    end
  end
  local buckets = { result.cpe, result.product_match }
  for _, rows in ipairs(buckets) do
    if type(rows) == "table" and #rows > 0 then
      return true
    end
  end
  return false
end

action = function(host, port)
  local product = port.version.product or port.version.name or ""
  local version = port.version.version or ""
  local extrainfo = port.version.extrainfo or ""
  local cpes = port.version.cpe or {}

  if (not version or version == "") and (not extrainfo or extrainfo == "") and #(cpes) == 0 then
    return nil
  end

  if version ~= "" and is_suppressed_fingerprint(product, version) then
    stdnse.debug1("vulnlocal: suppressed noisy fingerprint product=%s version=%s", product, version)
    return nil
  end

  local result = nil
  local err_api, err_db = nil, nil

  if API_ARG and API_ARG ~= "" then
    stdnse.debug1("vulnlocal: trying API %s product=%s version=%s extra=%s", API_ARG, product, version, extrainfo)
    result, err_api = correlate_via_api(API_ARG, product, version, cpes, extrainfo)
    if (not result or not result_has_hits(result)) and resolve_db() then
      if result and not result_has_hits(result) then
        stdnse.debug1("vulnlocal: API returned no hits; trying pack fallback")
        err_api = err_api or "api empty"
      end
      result = nil
    end
  end

  if not result then
    local dbpath = resolve_db()
    if dbpath then
      stdnse.debug1("vulnlocal: using pack %s product=%s version=%s", dbpath, product, version)
      result, err_db = correlate_via_db(dbpath, product, version, cpes, extrainfo)
    end
  end

  if not result then
    if API_ARG and API_ARG ~= "" and not DB_ARG and not resolve_db() then
      return string.format(
        "vulnlocal: API unreachable (%s) and no offline pack. Set vulnlocal.db=.../vulnlocal.pack",
        tostring(err_api or "fail")
      )
    end
    if API_ARG and API_ARG ~= "" then
      return string.format(
        "vulnlocal: API failed (%s); pack failed (%s)",
        tostring(err_api or "fail"),
        tostring(err_db or "no pack")
      )
    end
    return "vulnlocal: offline pack not found. Point vulnlocal.db at the vulnlocal.pack directory (forward slashes + quotes on Windows). Or use vulnlocal.api=http://127.0.0.1:8088"
  end

  -- Normalize API by_cpe groups (json may use different shapes)
  local by_cpe = {}
  if type(result.by_cpe) == "table" then
    for _, g in ipairs(result.by_cpe) do
      if type(g) == "table" and g.cpe and type(g.cves) == "table" then
        local rows = {}
        for _, item in ipairs(g.cves) do
          if type(item) == "table" and item.id then
            rows[#rows + 1] = {
              id = tostring(item.id),
              score = tonumber(item.score) or 0,
              title = tostring(item.title or ""),
              link = tostring(item.link or cve_link(tostring(item.id))),
            }
          end
        end
        if #rows > 0 then
          by_cpe[#by_cpe + 1] = { cpe = tostring(g.cpe), cves = rows }
        end
      end
    end
  end
  if #by_cpe == 0 then
    local flat = {}
    for _, rows in ipairs({ result.cpe or {}, result.product_match or {} }) do
      for _, r in ipairs(rows) do flat[#flat + 1] = r end
    end
    if #flat > 0 then
      by_cpe[1] = { cpe = synth_cpe(product, version), cves = flat }
    end
  end

  local text = format_vulners_style(by_cpe)
  if not text then
    return string.format(
      "No CVE matches for %s %s (checked %s).",
      product ~= "" and product or "(unknown)",
      version,
      tostring(result.source or "db/api")
    )
  end

  local structured = stdnse.output_table()
  structured["source"] = result.source or ""
  structured["match_mode"] = result.match_mode or "cpe_nvd_ranges"
  structured["product"] = (product .. " " .. version)
  structured["by_cpe"] = by_cpe
  structured["cpe"] = result.cpe or {}
  structured["product_match"] = result.product_match or {}

  return structured, text
end
