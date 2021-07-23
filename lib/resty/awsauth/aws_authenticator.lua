local signature_basic = require('resty.awsauth.signature_basic')
local util = require('resty.awsauth.util')


local _M = { _VERSION = '0.0.1' }


local mt = { __index = _M }
local date_difference_tolerance = 60 * 15
local credential_validate_time_length = 60 * 60 * 24 * 7
local auth_header_pattern_v4 = '^(.+)\\s+Credential=(.+),'..
                               '\\s*SignedHeaders=(.+),\\s*Signature=([0-9a-fA-F]+)$'
local auth_header_pattern_v2 = '^(\\w+)\\s+(.+):(.+)$'
local headers_not_need_to_be_signed = {
    ['x-amz-content-sha256'] = true
}
local parameters_to_check = {
    v4 = {
        ['X-Amz-Algorithm'] = 'algorithm',
        ['X-Amz-Credential'] = 'credential',
        ['X-Amz-Date'] = 'amz_date',
        ['X-Amz-Expires'] = 'expires',
        ['X-Amz-Signature'] = 'signature',
        ['X-Amz-SignedHeaders'] = 'signed_headers',
    },
    v2 = {
        ['AWSAccessKeyId'] = 'access_key',
        ['Expires'] = 'expires',
        ['Signature'] = 'signature',
    },
    post_v4 = {
        ['X-Amz-Algorithm'] = 'algorithm',
        ['X-Amz-Credential'] = 'credential',
        ['X-Amz-Date'] = 'amz_date',
        ['X-Amz-Signature'] = 'signature',
        ['key'] = false,
        ['Policy'] = false,
    },
    post_v2 = {
        ['AWSAccessKeyId'] = 'access_key',
        ['Signature'] = 'signature',
        ['key'] = false,
        ['Policy'] = false,
    },
}


local function find_out_auth_mechanism(ctx)
    ctx.anonymous = false
    local auth_header = ctx.headers.authorization
    local mechanisms = 0

    if auth_header ~= nil then
        ctx.query_auth = false
        mechanisms = mechanisms + 1
    end

    if ctx.args['X-Amz-Algorithm'] ~= nil then
        ctx.query_auth = true
        ctx.version = 'v4'
        mechanisms = mechanisms + 1
    end

    if ctx.args.Signature ~= nil then
        ctx.query_auth = true
        ctx.version = 'v2'
        mechanisms = mechanisms + 1
    end

    if mechanisms == 0 then
        ctx.anonymous = true
        return nil, nil, nil
    elseif mechanisms > 1 then
        return nil, 'InvalidArgument', 'Only one auth mechanism allowed; '..
                'only one of the X-Amz-Algorithm query parameter, Signature '..
                'query string parameter or the Authorization header '..
                'should be specified'
    end


    if ctx.query_auth == false then
        if type(auth_header) == 'table' then
            return nil, 'InvalidArgument', 'One and only one Authorization '..
                    'header is allowed'
        end

        if ngx.re.match(auth_header, auth_header_pattern_v4, "jo") then
            ctx.version = 'v4'
        elseif ngx.re.match(auth_header, auth_header_pattern_v2, "jo") then
            ctx.version = 'v2'
        else
            return nil, 'InvalidArgument', 'Authorization header is '..
                    'malformed: '..tostring(auth_header)
        end
    end

    return nil, nil, nil
end


local function parse_credential(ctx)
    local iterms = util.split(ctx.credential, '/')
    if #iterms ~= 5 then
        return nil, 'InvalidArgument', 'the credential is invalid: '..
                ctx.credential
    end

    ctx.access_key = iterms[1]
    ctx.credential_date = iterms[2]
    ctx.ragion = iterms[3]
    ctx.service = iterms[4]
    ctx.credential_scope = ctx.credential:sub(#iterms[1] + 2)

    return nil, nil, nil
end


function _M.get_access_key(args, authorization_header, post_parameters)
    if type(args) ~= 'table' then
        args = {}
    end

    if type(post_parameters) ~= 'table' then
        post_parameters = {}
    end

    if type(args['AWSAccessKeyId']) == 'string' then
        return args['AWSAccessKeyId']
    end

    if type(post_parameters['AWSAccessKeyId']) == 'string' then
        return post_parameters['AWSAccessKeyId']
    end

    if type(args['X-Amz-Credential']) == 'string' then
        return util.split(args['X-Amz-Credential'], '/')[1]
    end

    if type(post_parameters['X-Amz-Credential']) == 'string' then
        return util.split(post_parameters['X-Amz-Credential'], '/')[1]
    end

    if type(authorization_header) ~= 'string' then
        return nil
    end

    local _, access_key, _ = string.match(authorization_header,
                                          auth_header_pattern_v2)
    if access_key ~= nil then
        return access_key
    end

    local _, credential, _, _ = string.match(authorization_header,
                                             auth_header_pattern_v4)
    if credential == nil then
        return nil
    end

    return util.split(args['X-Amz-Credential'], '/')[1]
end


local function parse_and_validate_auth_header(ctx)
    if ctx.version == 'v4' then
        local m  = ngx.re.match(ctx.headers.authorization, auth_header_pattern_v4, "jo")
        local m = m or {}
        ctx.algorithm, ctx.credential, ctx.signed_headers, ctx.signature = m[1], m[2], m[3], m[4]
    else
        local m  = ngx.re.match(ctx.headers.authorization, auth_header_pattern_v2, "jo")
        local m = m or {}
        ctx.algorithm, ctx.access_key, ctx.signature =  m[1], m[2], m[3]
    end

    return nil, nil, nil
end


local function parse_and_validate_auth_parameters(ctx)
    local parameters_table, auth_type, to_check

    if ctx.is_post == true then
        parameters_table = ctx
        auth_type = 'post_' .. ctx.version
    else
        parameters_table = ctx.args
        auth_type = ctx.version
    end

    to_check = parameters_to_check[auth_type]

    for arg_name, var_name in pairs(to_check) do
        local arg_value

        if ctx.is_post == true then
            arg_value = parameters_table[arg_name:lower()]
        else
            arg_value = parameters_table[arg_name]
        end

        if arg_value == nil then
            return nil, 'AccessDenied', 'missing parameter: '..arg_name
        end

        if type(arg_value) ~= 'string' then
            return nil, 'InvalidArgument', string.format('invild value of '..
                    'perameter %s : %s', arg_name, arg_value)
        end

        if var_name ~= false then
            ctx[var_name] = arg_value
        end
    end

    return nil, nil, nil
end


local function parse_and_validate_auth_info(ctx)
    if ctx.query_auth == false then
        local _, err, msg = parse_and_validate_auth_header(ctx)
        if err ~= nil then
            return nil, err, msg
        end
    else
        local _, err, msg = parse_and_validate_auth_parameters(ctx)
        if err ~= nil then
            return nil, err, msg
        end
    end

    if ctx.credential ~= nil then
        local _, err, msg = parse_credential(ctx)
        if err ~= nil then
            return nil, err, msg
        end
    end

    return nil, nil, nil
end


local function get_date_info(ctx)
    local iso_date = ctx.amz_date or ctx.headers['x-amz-date']
    local http_date = ctx.headers['date']

    if iso_date == nil and http_date == nil then
        return nil, 'InvalidArgument', 'missing request date'
    end

    if iso_date ~= nil then
        local ts, err, msg = util.parse_iso_base_date(iso_date)
        if err ~= nil then
            return nil, err, msg
        end

        return {
            request_date = iso_date,
            request_ts = ts,
        }, nil, nil
    else
        local ts, err, msg = util.parse_http_date(http_date)
        if err ~= nil then
            return nil, err, msg
        end

        return {
            request_date = http_date,
            request_ts = ts,
        }, nil, nil
    end
end


local function validate_and_standardize_headers(signed_headers, headers)
    local signed_headers_table = {}

    for _, signed_header_name in ipairs(util.split(signed_headers, ';')) do
        signed_headers_table[signed_header_name] = true
    end

    local stand_headers = {}

    for k, v in pairs(headers) do
        local stand_name = util.strip(k)
        local stand_value

        if type(v) == 'string' then
            stand_value = util.trimall(v)
        elseif type(v) == 'table' then
            stand_value = {}
            for _, value in ipairs(v) do
                table.insert(stand_value, util.trimall(value))
            end
        else
            stand_value = ''
        end

        stand_headers[stand_name] = stand_value

        if headers_not_need_to_be_signed[stand_name] ~= true and
                (stand_name == 'host' or util.starts_with(stand_name, 'x-amz-')) and
                signed_headers_table[stand_name] ~= true then

            return nil, 'AccessDenied', 'There were headers present in the'..
                    'request which were not signed:' .. stand_name
         end
     end

    return stand_headers, nil, nil
end


local function check_credential_date(ts_now, credential_date)
    local date_ts, err, msg =
            util.parse_iso_base_date(credential_date .. 'T000000Z')
    if err ~= nil then
        return nil, err, msg
    end

    if ts_now > date_ts + credential_validate_time_length then
        return nil, 'InvalidArgument', string.format(
                'the credential has expired, credential_date: %s, ' ..
                'credential_date_ts: %f, ts_now: %f',
                credential_date, date_ts, ts_now)
    end

    return nil, nil, nil
end


local function get_body_content_sha256()
    ngx.req.read_body()
    local body_data = ngx.req.get_body_data() or ''

    return util.make_sha256(body_data, true)
end


local function authenticate_v4(ctx, allow_pure_v4)
    ctx.hashed_payload = ctx.headers['x-amz-content-sha256']

    if ctx.hashed_payload == nil then
        if allow_pure_v4 then
            local hashed_payload, err, errmsg = get_body_content_sha256()
            if err ~= nil then
                return nil, err, errmsg
            end
            ctx.hashed_payload = hashed_payload
        else
            ctx.hashed_payload = signature_basic.unsigned_payload
        end
    end

    local date_info,  err, msg = get_date_info(ctx)
    if err ~= nil then
        return nil, err, msg
    end
    ctx.request_date = date_info.request_date

    local request_ts = date_info.request_ts
    local ts_now = ngx.time()

    if ctx.query_auth == false then
        if request_ts < ts_now - date_difference_tolerance or
               request_ts > ts_now + date_difference_tolerance then
            return nil, 'RequestTimeTooSkewed', string.format(
                    'the difference between the request time and the '..
                    'server time is to large, request_date: %s, '..
                    'request_date_ts: %f, ts_now: %f',
                    date_info.request_date, date_info.request_ts, ts_now)
        end
    else
        local expires_ts = tonumber(ctx.expires)
        if expires_ts == nil then
            return nil, 'InvalidArgument', 'Expires format error: '..
                    tostring(ctx.expires)
        end
        if ts_now > request_ts + expires_ts then
            return nil, 'ExpiredToken', string.format(
                    'the token has expired, request_date: %s, '..
                    'request_date_ts: %f, expires_ts: %f, ts_now: %f',
                    date_info.request_date, date_info.request_ts,
                    expires_ts, ts_now)
        end
    end

    local _, err, msg = check_credential_date(ts_now, ctx.credential_date)
    if err ~= nil then
        return nil, err, msg
    end

    local encoded_args = signature_basic.uri_encode_args(ctx.args)

    ctx.canonical_query_string =
            signature_basic.build_canonical_query_string(encoded_args)

    local stand_headers, err, msg =
            validate_and_standardize_headers(ctx.signed_headers, ctx.headers)
    if err ~= nil then
        return nil, err, msg
    end

    ctx.canonical_headers =
            signature_basic.build_canonical_headers_v4(ctx.signed_headers,
                                                       stand_headers)

    ctx.canonical_request =
            signature_basic.build_canonical_request(ctx)

    ctx.hashed_canonical_request =
            util.make_sha256(ctx.canonical_request, true)

    ctx.string_to_sign = signature_basic.build_string_to_sign_v4(ctx)

    ctx.signing_key, ctx.cache_hit, ctx.no_memory, ctx.forcible =
            signature_basic.derive_signing_key(ctx.secret_key,
                                               ctx.credential_scope,
                                               ctx.shared_dict)

    local sig = signature_basic.calc_signature_v4(ctx.signing_key,
                                                  ctx.string_to_sign)

    if sig ~= ctx.signature then
        local msg = string.format('string to sign:%s, hex:%s\n'..
                                  'canonical_request:%s, hex:%s',
                                  ctx.string_to_sign,
                                  util.to_hex(ctx.string_to_sign),
                                  ctx.canonical_request,
                                  util.to_hex(ctx.canonical_request))
        return nil, 'SignatureDoesNotMatch', msg
    end

    return ctx, nil, nil
end


local function authenticate_v2(ctx)
    local ts_now = ngx.time()

    if ctx.query_auth then
        local ts = tonumber(ctx.expires)
        if ts == nil then
            return nil, 'InvalidArgument', 'Expires format error '
                    .. tostring(ctx.expires)
        end
        if ts < ts_now then
            return nil, 'ExpiredToken', string.format(
                    'the token has expired, expires: %f, ts_now: %f',
                    ts, ts_now)
        end
        ctx.date = ctx.expires
    else
        local date = ctx.headers['x-amz-date'] or ctx.headers.date
        if date == nil then
            return nil, 'AccessDenied', 'missing x-amz-date or date header'
        end

        local ts, err, msg = util.parse_http_date(date)
        if err ~= nil then
            return nil, err, msg
        end

        if ts < ts_now - date_difference_tolerance or
                  ts > ts_now + date_difference_tolerance then
            return nil, 'RequestTimeTooSkewed', string.format(
                    'the difference between the request time and the '..
                    'server time is to large, request_date: %s, '..
                    'request_date_ts: %f, ts_now: %f',
                    date, ts, ts_now)
        end

        if ctx.headers['x-amz-date'] ~= nil then
            ctx.date = ''
        else
            ctx.date = ctx.headers.date
        end
    end

    ctx.content_md5 = ctx.headers['Content-MD5'] or ''
    ctx.content_type = ctx.headers['content-type'] or ''

    ctx.canonical_headers =
            signature_basic.build_canonical_headers_v2(ctx.headers)

    ctx.canonical_resource =
            signature_basic.build_canonical_resource(ctx)

    ctx.string_to_sign =
            signature_basic.build_string_to_sign_v2(ctx)

    local sig = signature_basic.calc_signature_v2(ctx.secret_key,
                                                  ctx.string_to_sign)

    if sig ~= ctx.signature then
        local msg = string.format('string_to_sign:%s, hex:%s',
                                  ctx.string_to_sign,
                                  util.to_hex(ctx.string_to_sign))
        return nil, 'SignatureDoesNotMatch', msg
    end

    return ctx, nil, nil
end


function _M.authenticate(self, ctx)
    ctx = ctx or {}
    ctx.verb = ctx.verb or ngx.var.request_method
    ctx.uri = ctx.uri or util.split(ngx.var.request_uri, '?')[1]
    ctx.args = ctx.args or ngx.req.get_uri_args()
    ctx.headers = ctx.headers or ngx.req.get_headers()
    ctx.shared_dict = self.shared_dict

    local _, err, msg = find_out_auth_mechanism(ctx)
    if err ~= nil then
        return nil, err, msg
    end

    if ctx.anonymous == true then
        return ctx, nil, nil
    end

    local _, err, msg = parse_and_validate_auth_info(ctx)
    if err ~= nil then
        return nil, err, msg
    end

    local secret_key, err, msg = self.get_secret_key(ctx)
    if err ~= nil then
        return nil, err, msg
    end
    if type(secret_key) ~= 'string' then
        return nil, 'InternalError', 'secret_key return by get_secret_key '..
                'is invalid: '..tostring(secret_key)
    end

    ctx.secret_key = secret_key

    if ctx.version == 'v4' then
        ctx.uri = util.url_escape(util.url_unescape_plus(ctx.uri), '/~')
        return authenticate_v4(ctx, self.allow_pure_v4)
    else
        local host = ctx.headers.host
        if type(host) ~= 'table' then
            host = {host}
        end
        for _, h in ipairs(host) do
            local bucket_name, err, msg =self.get_bucket_from_host(h)
            if err ~= nil then
                return nil, err, msg
            end
            ctx.bucket_in_host = bucket_name
            if type(bucket_name) == 'string' then
                break
            end
        end
        return authenticate_v2(ctx)
    end
end


function _M.authenticate_post(self, ctx)
    if type(ctx) ~= 'table' then
        return nil, 'InvalidArgument', 'the argument to authenticate_post' ..
                ' must be a table which contains form fields'
    end

    local lower_ctx = {}
    for k, v in pairs(ctx) do
        local lower_k = k
        if type(k) == 'string' then
            lower_k = k:lower()
        end

        lower_ctx[lower_k] = v
    end

    ctx = lower_ctx

    ctx.is_post = true
    ctx.anonymous = false

    if ctx.policy == nil then
       ctx.anonymous = true
        return ctx, nil, nil
    end

    if ctx['x-amz-signature'] ~= nil then
        ctx.version = 'v4'
    elseif ctx.signature ~= nil then
        ctx.version = 'v2'
    else
        return nil, 'InvalidArgument', 'absence of signature in post field'
    end

    local _, err, msg = parse_and_validate_auth_parameters(ctx)
    if err ~= nil then
        return nil, err, msg
    end

    if ctx.credential ~= nil then
        local _, err, msg = parse_credential(ctx)
        if err ~= nil then
            return nil, err, msg
        end
    end

    local secret_key, err, msg = self.get_secret_key(ctx)
    if err ~= nil then
        return nil, err, msg
    end
    ctx.secret_key = secret_key

    local sig
    if ctx.version == 'v4' then
        ctx.signing_key, ctx.cache_hit, ctx.no_memory, ctx.forcible =
                signature_basic.derive_signing_key(ctx.secret_key,
                                                   ctx.credential_scope,
                                                   self.shared_dict)

        sig = signature_basic.calc_signature_v4(ctx.signing_key,
                                                ctx.policy)
    else
        sig = signature_basic.calc_signature_v2(ctx.secret_key,
                                                ctx.policy)
    end

    if sig ~= ctx.signature then
        local msg = string.format('Policy:%s, hex:%s',
                                  ctx.policy,
                                  util.to_hex(ctx.policy))
        return nil, 'SignatureDoesNotMatch', msg
    end

    return ctx, nil, nil
end


function _M.init_seed_signature(self, ctx)
    local ctx, err, msg = self:authenticate(ctx)
    if err ~= nil then
        return nil, err, msg
    end

    if ctx.anonymous == true then
        return nil, 'InvalidSignature',
                'anonymous user is not allowed to use chunked upload'
    end

    if ctx.version ~= 'v4' or ctx.query_auth ~= false then
        return nil, 'InvalidSignature',
                'chunked upload must use signature version 4 '..
                'with an Authorization header'
    end

    ctx.previous_signature = ctx.signature
    return ctx, nil, nil
end


function _M.check_chunk_signature(self, ctx, chunk_data_sha256,
                                  chunk_signature)
    ctx.chunk_data_sha256 = chunk_data_sha256
    ctx.chunk_string_to_sign =
            signature_basic.build_chunk_string_to_sign_v4(ctx)

    local chunk_sig = signature_basic.calc_signature_v4(
            ctx.signing_key, ctx.chunk_string_to_sign)

    if chunk_sig ~= chunk_signature then
        local msg = string.format('chunk string to sign:%s, hex:%s',
                                  ctx.chunk_string_to_sign,
                                  util.to_hex(ctx.chunk_string_to_sign))
        return nil, 'SignatureDoesNotMatch', msg
    end

    ctx.previous_signature = chunk_signature

    return ctx, nil, nil
end


function _M.new(get_secret_key, get_bucket_from_host, shared_dict, opts)
    opts = opts or {}

    return setmetatable({
        get_secret_key = get_secret_key,
        get_bucket_from_host = get_bucket_from_host,
        shared_dict = shared_dict,
        allow_pure_v4 = opts.allow_pure_v4 == true,
    }, mt)
end


return _M
