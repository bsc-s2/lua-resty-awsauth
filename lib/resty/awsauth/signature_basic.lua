local util = require('resty.awsauth.util')


local _M = {
    _VERSION = '0.0.1',

    empty_payload_hash = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    unsigned_payload = 'UNSIGNED-PAYLOAD',
}


local one_week = 60 * 60 * 24 * 7

-- true means that this arg can have value, false means can not
local valid_subresources = {
    ['accelerate'] = false,
    ['acl'] = false,
    ['cors'] = false,
    ['defaultObjectAcl'] = true,
    ['delete'] = true,
    ['lifecycle'] = false,
    ['location'] = true,
    ['logging'] = false,
    ['notification'] = true,
    ['partNumber'] = true,
    ['policy'] = false,
    ['replication'] = false,
    ['requestPayment'] = false,
    ['response-cache-control'] = true,
    ['response-content-disposition'] = true,
    ['response-content-encoding'] = true,
    ['response-content-language'] = true,
    ['response-content-type'] = true,
    ['response-expires'] = true,
    ['restore'] = true,
    ['storageClass'] = true,
    ['tagging'] = false,
    ['torrent'] = false,
    ['uploadId'] = true,
    ['uploads'] = false,
    ['versionId'] = true,
    ['versioning'] = true,
    ['versions'] = true,
    ['website'] = true,
    ['copy'] = false,
    ['relax'] = false,
    ['meta'] = false,
    ['additional_acl'] = false,
}


function _M.calc_signature_v4(signing_key, string_to_sign)
    return util.make_hmac_sha256(signing_key, string_to_sign, true)
end


function _M.calc_signature_v2(secret_key, string_to_sign)
    return ngx.encode_base64(ngx.hmac_sha1(secret_key, string_to_sign))
end


function _M.uri_encode_args(args)
    if type(args) == 'string' then
        return util.url_escape(args, '~')
    end

    if type(args) ~= 'table' then
        return args
    end

    local encoded_args = {}
    for k, v in pairs(args) do
        encoded_args[_M.uri_encode_args(k)] = _M.uri_encode_args(v)
    end

    return encoded_args
end


function _M.derive_signing_key(secret_key, credential_scope, shared_dict)
    local scope_items = util.split(credential_scope, '/')

    local key = table.concat({
                             secret_key,
                             scope_items[1],
                             scope_items[2],
                             scope_items[3],
                         }, ':')

    if shared_dict ~= nil then
        local signing_key = shared_dict:get(key)
        if signing_key ~= nil then
            return signing_key, true, false, false
        end
    end

    local kDate = util.make_hmac_sha256("AWS4" .. secret_key, scope_items[1])
    local kRegion = util.make_hmac_sha256(kDate, scope_items[2])
    local kService = util.make_hmac_sha256(kRegion, scope_items[3])
    local kSigning = util.make_hmac_sha256(kService, scope_items[4])

    local cache_no_memory = false
    local cache_forcible = false

    if shared_dict ~= nil then
        local _, err, forcible = shared_dict:set(key, kSigning, one_week)
        if err ~= nil then
            cache_no_memory = true
        end
        cache_forcible = forcible
    end

    return kSigning, false, cache_no_memory, cache_forcible
end


function _M.build_canonical_query_string(encoded_args)
    local arg_names = {}
    for k, _ in pairs(encoded_args) do
        if k ~= 'X-Amz-Signature' then
            table.insert(arg_names, k)
        end
    end

    table.sort(arg_names)

    local key_value_strs = {}
    for _, name in ipairs(arg_names) do
        local value = encoded_args[name]

        if type(value) == 'table' then
            value = value[1]
        end

        if type(value) ~= 'string' then
            value = ''
        end

        table.insert(key_value_strs, name .. '=' .. value)
    end

    return table.concat(key_value_strs, '&')
end


function _M.build_canonical_headers_v4(signed_headers, headers)
    local r = {}

    for _, name in ipairs(util.split(signed_headers, ';')) do
        local value = headers[name]
        local value_str

        if type(value) == 'table' then
            value_str = table.concat(value, ',')
        elseif type(value) == 'string' then
            value_str = value
        else
            value_str = ''
        end

        table.insert(r, name .. ':' .. value_str)
    end

    return table.concat(r, '\n') .. '\n'
end


function _M.build_canonical_request(ctx)
    local canonical_request = {
        ctx.verb,
        ctx.uri,
        ctx.canonical_query_string,
        ctx.canonical_headers,
        ctx.signed_headers,
        ctx.hashed_payload
    }
    return table.concat(canonical_request, '\n')
end


function _M.build_string_to_sign_v4(ctx)
    local string_to_sign = {
        ctx.algorithm,
        ctx.request_date,
        ctx.credential_scope,
        ctx.hashed_canonical_request
    }
    return table.concat(string_to_sign, '\n')
end


function _M.build_chunk_string_to_sign_v4(ctx)
    local string_to_sign = {
        'AWS4-HMAC-SHA256-PAYLOAD',
        ctx.request_date,
        ctx.credential_scope,
        ctx.previous_signature,
        _M.empty_payload_hash,
        ctx.chunk_data_sha256,
    }
    return table.concat(string_to_sign, '\n')
end


function _M.build_canonical_headers_v2(headers)
    local amz_header_names = {}

    for k, _ in pairs(headers) do
        if util.starts_with(k, 'x-amz-') then
            table.insert(amz_header_names, k)
        end
    end

    table.sort(amz_header_names)

    local r = {}
    for _, name in ipairs(amz_header_names) do
        if type(headers[name]) == 'table' then
            table.insert(r, name .. ':' ..
                         table.concat(headers[name], ','))
        else
            table.insert(r, name .. ':' .. headers[name])
        end
    end

    return table.concat(r, '\n')
end


function _M.build_canonical_resource(ctx)
    local res = ''

    local bucket_name = ctx.bucket_in_host
    if type(bucket_name) == 'string' and #bucket_name > 0 then
        res = res .. '/' .. bucket_name
    end

    res = res .. ctx.uri

    if res == '' then
        res = res .. '/'
    end

    local subresources= {}
    for k, _ in pairs(ctx.args) do
        if valid_subresources[k] ~= nil then
            table.insert(subresources, k)
        end
    end

    table.sort(subresources)

    local arg_values = {}
    for _, name in ipairs(subresources) do
        local v = ctx.args[name]
        if type(v) == 'table' then
            return nil, 'InvalidArgument', 'duplicated arg: '..name
        elseif v == true or valid_subresources[name] == false then
            table.insert(arg_values, name)
        else
            table.insert(arg_values, name .. '=' .. v)
        end
    end

    if #subresources > 0 then
        res = res .. '?' .. table.concat(arg_values, '&')
    end

    return  res
end


function _M.build_string_to_sign_v2(ctx)
    local string_to_sign = {
        ctx.verb,
        ctx.content_md5,
        ctx.content_type,
        ctx.date,
    }

    if ctx.canonical_headers ~= '' then
        table.insert(string_to_sign, ctx.canonical_headers)
    end

    table.insert(string_to_sign, ctx.canonical_resource)

    return table.concat(string_to_sign, '\n')
end


return _M
