local ffi = require('ffi')
local resty_sha256 = require('resty.sha256')
local resty_string = require('resty.string')


local _M = { _VERSION = '0.0.1' }


local time_zone = -60 * 60 * 8
local iso_basic_pattern = '(%d%d%d%d)(%d%d)(%d%d)T(%d%d)(%d%d)(%d%d)Z'
local iso_basic_format = '%04d%02d%02dT%02d%02d%02dZ'


ffi.cdef[[
typedef struct env_md_st EVP_MD;
unsigned char *HMAC(const EVP_MD *evp_md, const void *key, int key_len,
                    const unsigned char *d, size_t n, unsigned char *md,
                    unsigned int *md_len);
const EVP_MD *EVP_sha256(void);
]]
local buf = ffi.new('char[?]', 32)
local md_len = ffi.new('int[?]', 1)
local evp_md = ffi.C.EVP_sha256()


function _M.make_sha256(str, to_hex)
    local sha256 = resty_sha256:new()
    sha256:update(str)
    local result = sha256:final()

    if to_hex == true then
        result = resty_string.to_hex(result)
    end

    return result
end


function _M.make_hmac_sha256(key, msg, to_hex)
	ffi.C.HMAC(evp_md, key, #key, msg, #msg, buf, md_len)
    local result = ffi.string(buf, 32)

    if to_hex == true then
        result = resty_string.to_hex(result)
    end

    return result
end


function _M.split(str, pat, plain)
    local t = {}

    if pat == '' then
        for i = 1, #str do
            table.insert(t, str:sub(i, i))
        end
        t[1] = t[1] or ''
        return t
    end

    local last_end, s, e
    last_end = 1
    s = 1

    while s do
        s, e = string.find(str, pat, last_end, plain)
        if s then
            table.insert(t, str:sub(last_end, s-1))
            last_end = e + 1
        end
    end

    table.insert(t, str:sub(last_end))
    return t
end


function _M.trimall(str)
    local r = str:gsub('^%s+', ''):gsub('%s+$', ''):gsub('%s+', ' ')
    return r
end


function _M.strip(str)
    local r = str:gsub('^%s+', ''):gsub('%s+$', '')
    return r
end


function _M.starts_with(s, pref)
    return s:sub(1, pref:len()) == pref
end


function _M.url_escape(str, safe)
    safe = safe or '/'
    local pattern = '^A-Za-z0-9%-%._'.. safe

    str = str:gsub('['.. pattern .. ']',
                   function(c) return string.format('%%%02X',string.byte(c)) end)
    return str
end


function _M.url_escape_plus(str, safe)
    local s

    safe = safe or ''

    if str:find(' ') ~= nil then
        s = _M.url_escape(str, safe .. ' ')
        return s:gsub(' ', '+')
    end

    return _M.url_escape(str, safe)
end


function _M.url_unescape(str)
   str = str:gsub('%%(%x%x)',function(x) return string.char(tonumber(x,16)) end)
   return str
end


function _M.url_unescape_plus(str)
    str = str:gsub('+', ' ')
    return _M.url_unescape(str)
end


function _M.dup(tbl, deep, ref_table)
    if type(tbl) ~= 'table' then
        return tbl
    end

    ref_table = ref_table or {}

    if ref_table[tbl] ~= nil then
        return ref_table[tbl]
    end

    local t = {}
    ref_table[tbl] = t

    for k, v in pairs(tbl) do
        if deep then
            if type(v) == 'table' then
                v = _M.dup(v, deep, ref_table)
            end
        end
        t[k] = v
    end
    return setmetatable(t, getmetatable(tbl))
end


function _M.parse_iso_base_date(date_str)
    if type(date_str) ~= 'string' then
        return nil, 'InvalidArgument', 'invalid time: '..tostring(date_str)
    end

    local yy, mm, dd, h, m, s = string.match(date_str, iso_basic_pattern)
    if yy == nil then
        return nil, 'InvalidArgument',
                'invalid iso 8601 base date format: '..date_str
    end

    local ts = os.time({ year=yy, month=mm, day=dd, hour=h, min=m, sec=s })

    return ts - time_zone, nil, nil
end


function _M.parse_http_date(date_str)
    --to suport this unstandard format: tue, 7 apr 2015 03:07:11 +0000
    --convert it to standard format: tue, 07 apr 2015 03:07:11 +0000
    if date_str:sub(7, 7) == ' ' then
        date_str = date_str:sub(1, 5) .. 0 .. date_str:sub(6)
    end

    local ts = ngx.parse_http_time(date_str)
    if ts == nil then
        return nil, 'invalidargument', 'invalid time format ' .. date_str
    end

    return ts, nil, nil
end


function _M.get_iso_base_now()
    local d = os.date('*t', os.time() + time_zone)
    return string.format(iso_basic_format, d.year, d.month, d.day,
                         d.hour, d.min, d.sec)
end


return _M
