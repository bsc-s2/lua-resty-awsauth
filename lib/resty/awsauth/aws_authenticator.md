Name
====

resty.awsauth.aws_authenticator - Lua module for authenticating a request with aws signature version 4 or versrion 2.

Table of Contents
=================

* [Name](#name)
* [Synopsis](#synopsis)
* [Description](#description)
* [Methods](#methods)
    * [new](#new)
    * [authenticate](#authenticate)
    * [authenticate_post](#authenticate_post)
    * [init_seed_signature](#init_seed_signature)
    * [check_chunk_signature](#check_chunk_signature)
* [Author](#author)
* [Copyright and License](#copyright-and-license)
* [See Also](#see-also)

Synopsis
========

```nginx
worker_processes  1;
error_log /tmp/lua_resty_awsauth_test.error.log debug;
pid /tmp/lua_resty_awsauth_test.nginx.pid;

worker_rlimit_nofile 1024;

events {
    worker_connections 1024;
}

http {
    lua_shared_dict signing_key 1m;

    access_log /tmp/lua_resty_awsauth_test.access.log;
    default_type text/plain;

    # you may need to change the path depending on where the lib is installed.
    lua_package_path '/usr/local/lib/lua/?.lua;;';
    lua_package_cpath '/usr/local/lib/lua/?.so;;';

    server {
        listen 1313;

        location / {

            rewrite_by_lua_block {
                local aws_authenticator = require("resty.awsauth.aws_authenticator")
                local upload = require("resty.upload")

                local users = {
                    renzhi = {
                        access_key = 'renzhi_access_key',
                        secret_key = 'renzhi_secret_key',
                    },
                    test_user = {
                        access_key = 'test_user_access_key',
                        secret_key = 'test_user_secret_key',
                    },
                }

                local domains = {
                    "storage.renzhi.com",
                    "renzhi.com",
                    "localhost",
                }


                local function get_secret_key(access_key)
                    for _, auth_info in pairs(users) do
                        if auth_info.access_key == access_key then
                            return auth_info.secret_key, nil, nil
                        end
                    end
                    return nil, 'InvalidAccessKey', 'the access key does not exists: ' .. access_key
                end


                local function get_user_name(access_key)
                    for user_name, auth_info in pairs(users) do
                        if auth_info.access_key == access_key then
                            return user_name, nil, nil
                        end
                    end
                    return nil, 'InvalidAccessKey', 'the access key does not exists: ' .. access_key
                end


                local function get_bucket_from_host(host)
                    if #host == 0 then
                        return nil
                    end

                    if string.match(host, '%d+%.%d+%.%d+%.%d+') then
                        return nil
                    end

                    for _, domain in ipairs(domains) do
                        local s, e = string.find(host, '.' .. domain, 1, true)
                        if e == #host then
                            local bucket_name = host:sub(1, s - 1)
                            if #bucket_name > 0 then
                                return bucket_name
                            end
                        end
                    end

                    return host
                end


                local function get_form_fields()
                    local form, err = upload:new(8192)
                    if err ~= nil then
                        return nil, 'InternalError', 'failed to new upload: ' .. err
                    end

                    form:set_timeout(5000)

                    local fields = {}
                    local k = ''

                    while true do
                        local typ, res, err = form:read()
                        if err ~= nil then
                            return nil, 'InternalError', 'failed to read fields: ' .. err
                        end

                        if typ == 'eof' then
                            break
                        elseif typ == 'header' then
                            local disposition = res[2]
                            local _, v_start = string.find(disposition, 'name="')
                            local v_end, _ = string.find(disposition, '"', v_start + 1)
                            k = string.sub(disposition, v_start + 1, v_end - 1)
                        elseif typ == 'body' then
                            fields[k] = (fields[k] or '') .. res
                        end
                    end

                    return fields
                end


                local authenticator = aws_authenticator.new(get_secret_key,
                                                            get_bucket_from_host,
                                                            ngx.shared.signing_key)

                local ctx, fields, err, msg, is_post_upload

                if ngx.var.request_method == 'POST' and ngx.var.request_uri == '/' then
                    fields, err, msg = get_form_fields()
                    if err ~= nil then
                        ngx.status = 500
                        ngx.say(string.format("faild to get form fields: %s, %s", err, msg))
                        ngx.exit(ngx.HTTP_OK)
                    end

                    ctx, err, msg = authenticator:authenticate_post(fields)
                else
                    ctx, err, msg = authenticator:authenticate()
                end

                if err ~= nil then
                    ngx.status = 403
                    ngx.say(string.format("authenticate failed: %s, %s", err, msg))
                    ngx.eof()
                    ngx.exit(ngx.HTTP_OK)
                end

                if ctx.anonymous == true then
                    ngx.status = 403
                    ngx.say(string.format("this service does not allow anonymous access"))
                    ngx.eof()
                    ngx.exit(ngx.HTTP_OK)
                end

                if ctx.version == 'v4' then
                    ngx.log(ngx.INFO, string.format("cache info: cache hit: %s, no memory: %s, forcible: %s",
                            tostring(ctx.cache_hit), tostring(ctx.no_memory), tostring(ctx.forcible)))
                end

                local user_name, err, msg = get_user_name(ctx.access_key)
                if err ~= nil then
                    ngx.say(string.format("faild to get user name by access key: %s, %s", err, msg))
                end

                -- do some service
            }
        }
    }
}
```

[Back to TOC](#table-of-contents)

Description
===========

This module provides API to help the OpenResty/ngx_lua user porgrammers to authenticate a request, which
have signature of version 4 or version 2. It can also athenticate the browser-based uploads request.

Methods
=======

[Back to TOC](#table-of-contents)

new
---
**syntax:** `obj, err, msg = class.new(get_secret_key, get_bucket_from_host, shared_dict)`

Instantiates an object of this class. The `class` value is returned by the call `require "resty.aws_signature.aws_authenticator"`.
This method takes the following arguments:

* `get_secret_key` is a callback function you need to impliment. The only parameter to this function
    is the access key found in the request, and the return value should be the corresponding secret key.

* `get_bucket_from_host` is a callback function you need to impliment. The only parameter to this function
    is the host header value, and the return value should be the bucket name in the host,
    this function is only used when authenticating signatrue of version 2.

* `shared_dict` is the name of the lua_shared_dict shm zone, which will be used to cache the signing key,
    it can be omited, if you do not want to cache the signing key.

[Back to TOC](#table-of-contents)

authenticate
--------
**syntax:** `ctx, err, msg = obj:authenticate(ctx)`

[Back to TOC](#table-of-contents)

authenticate the signature in the request.

This method takes the following arguments:

* `ctx` is a lua table which contain all information about the request.  It can be omited.
    It may contain the following keys:

 - `verb` the request method, such as 'PUT', 'GET'. If this key is omited, we will set it with value
    get from `ngx.var.request_method`

 - `uri` the request uri, should not contain the query string. If this key is omited, we will set it with
    value get from `util.split(ngx.var.request_uri, '?')[1]')`

 - `args` the request args. If this key is omited, we will set it with value get from `ngx.req.get_uri_args()`

 - `headers` the request headers. If this key is omited, we will set it with value get from `ngx.req.get_headers()`

The return values depend on the following cases:

* If authentication succeed, the method will return a lua table which contains come intermidiate values
    used in the authenticating process, it is usefull for debuging. It may contains the following keys:

 - `anonymous` is a boolean value to indicate whether the request is signed, if not, this value is set to `true`.

 - `access_key` the access key specified in the request.

 - `version` is 'v4' or 'v2' to indicate the vesion of the signature.

 - `string_to_sign` is the string used to calculate the signatrue.

 - `signing_key` is the key used to calculate the signatrue, which is derived from secret key.

 - `cache_hit` is boolean value to indicate whether the `signing_key` is get from the cache. If you did not
    specified a shared dict, it will always be `false`.

 - `no_memory` is boolean value to indicate whether the cache is lack of memory. If you did not
    specified a shared dict, it will always be `false`.

 - `forcible` is boolean value to indicate whether other valid items have been removed forcibly when out
    of storage in the shared memory zone. If you did not specified a shared dict, it will always be `false`.

* If something go wrong, this method will return a nil and an error code and an error message.


authenticate_post
--------
**syntax:** `ctx, err, msg = obj:authenticate_post(form_fields)`

[Back to TOC](#table-of-contents)

authenticate the signature in the request, if the request is browser-based uploads using POST.

This method takes the following arguments:

* `form_fields` is a lua table which contains the form fields in the POST request, if do not need to
    contain the 'file' fields.

The return values depend on the following cases:

* If authentication succeed, the method will return a lua table which contains come intermidiate values
    used in the authenticating process, it is usefull for debuging. It may contains the following keys:

 - `anonymous` is a boolean value to indicate whether the request is signed, if not, this value is set to `true`.

 - `access_key` the access key specified in the request.

 - `version` is 'v4' or 'v2' to indicate the vesion of the signature.

 - `policy` is the string used to calculate the signatrue.

 - `signing_key` is the key used to calculate the signatrue, which is derived from secret key.

 - `cache_hit` is boolean value to indicate whether the `signing_key` is get from the cache. If you did not
    specified a shared dict, it will always be `false`.

 - `no_memory` is boolean value to indicate whether the cache is lack of memory. If you did not
    specified a shared dict, it will always be `false`.

 - `forcible` is boolean value to indicate whether other valid items have been removed forcibly when out
    of storage in the shared memory zone. If you did not specified a shared dict, it will always be `false`.

* If something go wrong, this method will return a nil and an error code and an error message.

init_seed_signature
--------
**syntax:** `ctx, err, msg = obj:init_seed_signature(ctx)`

[Back to TOC](#table-of-contents)

calculate the seed signature of a chunked upload request, the argument `ctx`
is the same as argument of `authenticate`

The return values is the same as the return of `authenticate`.

check_chunk_signature
--------
**syntax:** `ctx, err, msg = obj:check_chunk_signature(ctx, chunk_data_sha256, chunk_signature)`

[Back to TOC](#table-of-contents)

This method takes the following arguments:

* `ctx` is the ctx returned by `init_seed_signature`.

* `chunk_data_sha256` is the sha256 of data of the chunk about to check.

* `chunk_signature` is the signature in the chunk about to check.

if the `chunk_signature` does not match the signature calculated by server,
nil and error code and error message will be returned

Author
======

Renzhi (任稚) <zhi.ren@baishancloud.com>.

[Back to TOC](#table-of-contents)

Copyright and License
=====================

The MIT License (MIT)

Copyright (c) 2016 Renzhi (任稚) <zhi.ren@baishancloud.com>

[Back to TOC](#table-of-contents)
