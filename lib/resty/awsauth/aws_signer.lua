local signature_basic = require('resty.awsauth.signature_basic')
local util = require('resty.awsauth.util')


local _M = { _VERSION = '0.0.1' }


local mt = { __index = _M }
local auth_formt_v4 = '%s Credential=%s, SignedHeaders=%s, Signature=%s'
local algorithm = 'AWS4-HMAC-SHA256'
local credential_suffix = 'aws4_request'
local valid_auth_args = {
    ['X-Amz-Algorithm'] = true,
    ['X-Amz-Credential'] = true,
    ['X-Amz-Date'] = true,
    ['X-Amz-Expires'] = true,
    ['X-Amz-SignedHeaders'] = true,
    ['X-Amz-Signature'] = true,
}


function _M.new(access_key, secret_key, opts)
    opts = opts or {}

    if type(access_key) ~= 'string' then
        return nil, 'InvalidArgument', string.format(
                'access_key: %s, in not a string', tostring(access_key))
    end

    if type(secret_key) ~= 'string' then
        return nil, 'InvalidArgument', string.format(
                'secret_key: %s, in not a string', tostring(secret_key))
    end

    local region = opts.region or 'us-east-1'
    if type(region) ~= 'string' then
        return nil, 'InvalidArgument', string.format(
                'region: %s, in not a string', tostring(region))
    end

    local service = opts.service or 's3'
    if type(service) ~= 'string' then
        return nil, 'InvalidArgument', string.format(
                'service: %s, in not a string', tostring(service))
    end

    local default_expires = opts.default_expires or 60
    if default_expires ~= nil and type(default_expires) ~= 'number' then
        return nil, 'InvalidArgument', string.format(
                'default_expires: %s, in not a number',
                tostring(default_expires))
    end

    return setmetatable({
        access_key = access_key,
        secret_key = secret_key,
        region = region,
        service = service,
        default_expires = default_expires or 60 * 15,
        shared_dict = opts.shared_dict,
    }, mt), nil, nil
end


local function query_string_to_args(query_string)
    local args = {}
    local items = util.split(query_string, '&')

    for _, item in ipairs(items) do
        local name_and_value = util.split(item, '=')
        local arg_name = name_and_value[1]
        local arg_value = name_and_value[2]

        arg_name = util.url_unescape_plus(arg_name)
        if args[arg_name] == nil then
            args[arg_name] = {}
        end

        if arg_value == nil then
            table.insert(args[arg_name], true)
        else
            table.insert(args[arg_name], util.url_unescape_plus(arg_value))
        end
    end

    for arg_name, arg_value in pairs(args) do
        if #arg_value == 1 then
            args[arg_name] = arg_value[1]
        end
    end

    return args
end


local function args_to_query_string(args)
    local qs = {}
    local encoded_args = signature_basic.uri_encode_args(args)

    for arg_name, arg_value in pairs(encoded_args) do
        if type(arg_value) == 'table' then
            for _, value in ipairs(arg_value) do
                if type(value) == 'string' then
                    table.insert(qs, arg_name .. '=' .. value)
                elseif value == true then
                    table.insert(qs, arg_name)
                end
            end

        elseif type(arg_value) == 'string' then
            table.insert(qs, arg_name .. '=' .. arg_value)

        elseif arg_value == true then
            table.insert(qs, 1, arg_name)
        end
    end

    return table.concat(qs, '&')
end


local function clean_query_string(query_string)
    local items = util.split(query_string, '&')
    local qs = {}

    for _, item in ipairs(items) do
        local arg_name = util.split(item, '=')[1]

        arg_name = util.url_unescape_plus(arg_name)

        if valid_auth_args[arg_name] ~= true then
            table.insert(qs, item)
        end
    end

    return table.concat(qs, '&')
end


local function clean_args(args)
    for arg_name, _ in pairs(valid_auth_args) do
        args[arg_name] = nil
    end

    return args
end


local function standardize_headers(headers, headers_not_to_sign)
    local headers_not_to_sign_table = {}
    for _, h in ipairs(headers_not_to_sign) do
        headers_not_to_sign_table[h:lower()] = true
    end

    local stand_headers = {}

    for k, v in pairs(headers) do
        local low_name = util.strip(k:lower())
        local stand_v = util.trimall(tostring(v))

        if stand_headers[low_name] == nil then
            stand_headers[low_name] = {}
        end

        table.insert(stand_headers[low_name], stand_v)
    end

    for k, v in pairs(stand_headers) do
        if #v == 1 then
            stand_headers[k] = v[1]
        end
    end

    local signed_header_names = {}
    for h_name, _ in pairs(stand_headers) do
        if headers_not_to_sign_table[h_name] ~= true then
            table.insert(signed_header_names, h_name)
        end
    end

    table.sort(signed_header_names)

    return table.concat(signed_header_names, ';'), stand_headers
end


local function validate_arg_value(arg_value)
    if arg_value == true or type(arg_value) == 'string' then
        return nil, nil, nil
    end

    if type(arg_value) ~= 'table' then
        return nil, 'InvalidArgument', string.format(
                'invalid arg value: %s, must be string or table or true',
                tostring(arg_value))
    end

    for _, value in ipairs(arg_value) do
        if type(value) ~= 'string' and value ~= true then
            return nil, 'InvalidArgument', string.format(
                    'invalid multi arg value: %s, must be string or true',
                    tostring(value))
        end
    end

    return nil, nil, nil
end


local function validate_uri_and_args(uri, args)
    if type(uri) ~= 'string' or
            not util.starts_with(uri, '/') then
        return nil, 'InvalidArgument', string.format(
                'uri: %s, must be a string and starts with /',
                tostring(uri))
    end

    local has_query_string
    if #util.split(uri, '?') > 1 then
        has_query_string = true
    end

    if has_query_string == true and args ~= nil then
        return nil, 'InvalidArgument', 'use both query string and args' ..
                ' is not allowed'
    end

    if args == nil then
        return nil, nil, nil
    end

    if type(args) ~= 'table' then
        return nil, 'InvalidArgument', string.format(
                'args: %s, is not a table', tostring(args))
    end

    for arg_name, arg_value in pairs(args) do
        if type(arg_name) ~= 'string' then
            return nil, 'InvalidArgument', string.format(
                    'arg name: %s, is not a string', tostring(arg_name))
        end

        local _, err, msg = validate_arg_value(arg_value)
        if err ~= nil then
            return nil, err, msg
        end
    end
end


local function validate_headers(headers)
    if type(headers) ~= 'table' then
        return nil, 'InvalidArgument', string.format(
                'headers: %s, is not a table', tostring(headers))
    end

    local has_host
    for k, v in pairs(headers) do
        if type(k) ~= 'string' then
            return nil, 'InvalidArgument', string.format(
                    'header name: %s, is not a string', tostring(k))
        end

        if type(v) ~= 'string' and type(v) ~= 'number' then
            return nil, 'InvalidArgument', string.format(
                    'header value: %s, must a string or a number', tostring(v))
        end

        if k:lower() == 'host' then
            has_host = true
        end
    end

    if has_host ~= true then
        return nil, 'InvalidArgument', 'absence of host header'
    end

    return nil, nil, nil
end


local function validate_request(request)
    if type(request) ~= 'table' then
        return nil, 'InvalidArgument', string.format(
                'request: %s, is not a table', tostring(request))
    end

    if type(request.verb) ~= 'string' then
        return nil, 'InvalidArgument', string.format(
                'request verb: %s, is not a string', tostring(request.verb))
    end

    local _, err, msg = validate_uri_and_args(request.uri, request.args)
    if err ~= nil then
        return nil, err, msg
    end

    local _, err, msg = validate_headers(request.headers)
    if err ~= nil then
        return nil, err, msg
    end

    return nil, nil, nil
end


local function modify_request_headers(request, query_auth, request_date, service_name)
    local has_amz_date
    local hashed_payload

    for k, v in pairs(request.headers) do
        local low_name = k:lower()

        if low_name == 'authorizatoin' then
            request.headers[k] = nil

        elseif low_name == 'x-amz-date' then
            has_amz_date = true
            request.headers[k] = nil

        elseif low_name == 'x-amz-content-sha256' then
            hashed_payload = v
            if service_name == 's3' and query_auth ~= true then
                request.headers[k] = nil
            end
        end
    end

    if has_amz_date == true or query_auth ~= true then
        request.headers['X-Amz-Date'] = request_date
    end

    if hashed_payload == nil then
        if type(request.body) == 'string' and #request.body > 0 then
            hashed_payload = util.make_sha256(request.body, true)
        else
            hashed_payload = signature_basic.empty_payload_hash
        end
    end

    if service_name == 's3' then
        if query_auth ~= true then
            request.headers['X-Amz-Content-SHA256'] = hashed_payload
        else
            hashed_payload = signature_basic.unsigned_payload
        end
    end

    return hashed_payload
end


function _M.add_auth_v4(self, request, opts)
    if opts ~= nil and type(opts) ~= 'table' then
        return nil, 'InvalidArgument', string.format(
                'opts: %s, is not a table', tostring(opts))
    end
    opts = opts or {}
    opts.query_auth = opts.query_auth== true
    opts.sign_payload = opts.sign_payload == true
    opts.headers_not_to_sign = opts.headers_not_to_sign or {}

    if type(opts.headers_not_to_sign) ~= 'table' then
        return nil, 'InvalidArgument', string.format(
                'headers_not_to_sign: %s, is not a table',
                tostring(opts.headers_not_to_sign))
    end

    if opts.sign_payload ~= true then
        table.insert(opts.headers_not_to_sign, 'x-amz-content-sha256')
    end

    local _, err, msg = validate_request(request)
    if err ~= nil then
        return nil, err, msg
    end

    local request_date = util.get_iso_base_now()
    local credential_date = string.sub(request_date, 1, 8)
    local credential_scope = table.concat({
                                          credential_date,
                                          self.region,
                                          self.service,
                                          credential_suffix
                                      }, '/')
    local credential = self.access_key .. '/' .. credential_scope

    local hashed_payload = modify_request_headers(request, opts.query_auth,
                                                  request_date, self.service)
    local signed_headers, stand_headers =
            standardize_headers(request.headers, opts.headers_not_to_sign)

    local uri_items = util.split(request.uri, '?')
    local origin_uri_path = uri_items[1]
    local origin_query_string = uri_items[2]

    local ctx = {
        verb = request.verb,
        uri = util.url_escape(util.url_unescape_plus(origin_uri_path), '/~'),

        algorithm = algorithm,
        request_date = request_date,
        credential_scope = credential_scope,
        signed_headers = signed_headers,
        hashed_payload = hashed_payload,
    }

    local cleaned_origin_query_string, query_string_from_args, args

    if origin_query_string ~= nil then
        cleaned_origin_query_string = clean_query_string(origin_query_string)
        args = query_string_to_args(cleaned_origin_query_string)
    else
        args = clean_args(request.args or {})
        query_string_from_args = args_to_query_string(args)
    end

    local auth_args
    if opts.query_auth == true then
        local amz_expires = tostring(tonumber(opts.expires) or
                                     self.default_expires)
        auth_args = {
            ['X-Amz-Algorithm'] = algorithm,
            ['X-Amz-Credential'] = credential,
            ['X-Amz-Date'] = request_date,
            ['X-Amz-Expires'] = amz_expires,
            ['X-Amz-SignedHeaders'] = ctx.signed_headers,
        }

        for k, v in pairs(auth_args) do
            args[k] = v
        end
    end

    local encoded_args = signature_basic.uri_encode_args(args)

    ctx.canonical_query_string =
            signature_basic.build_canonical_query_string(encoded_args)

    ctx.canonical_headers =
            signature_basic.build_canonical_headers_v4(signed_headers,
                                                    stand_headers)

    ctx.canonical_request = signature_basic.build_canonical_request(ctx)

    ctx.hashed_canonical_request =
            util.make_sha256(ctx.canonical_request, true)

    ctx.string_to_sign = signature_basic.build_string_to_sign_v4(ctx)

    ctx.signing_key, ctx.cache_hit, ctx.no_memory, ctx.forcible =
            signature_basic.derive_signing_key(self.secret_key,
                                               credential_scope,
                                               self.shared_dict)

    ctx.signature = signature_basic.calc_signature_v4(ctx.signing_key,
                                                      ctx.string_to_sign)

    local qs
    if origin_query_string ~= nil then
        qs = origin_query_string
    else
        qs = query_string_from_args
    end

    if opts.query_auth == true then
        if #qs ~= 0 then
            qs = qs .. '&'
        end

        qs = qs .. args_to_query_string(auth_args) ..
                '&X-Amz-Signature=' .. ctx.signature

        request.uri = origin_uri_path .. '?' .. qs
    else
        if #qs ~= 0 then
            request.uri = origin_uri_path .. '?' .. qs
        else
            request.uri = origin_uri_path
        end

        request.headers['Authorization'] = string.format(auth_formt_v4,
                ctx.algorithm, credential, ctx.signed_headers, ctx.signature)
    end

    return ctx, nil, nil
end


return _M
