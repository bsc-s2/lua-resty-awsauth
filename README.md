Name
====

lua-resty-awsauth - Lua library for signing a request with signature version 4 or authenticating a request which is signed by signature version 4 or by signatrue version 2

Table of Contents
=================

* [Name](#name)
* [Status](#status)
* [Synopsis](#synopsis)
* [Demo](#demo)
* [Description](#description)
* [Installation](#installation)
* [Author](#author)
* [Copyright and License](#copyright-and-license)

Status
======

This library is already usable though still highly experimental.

The Lua API is still in flux and may change in the near future without notice.

Synopsis
========

[Back to TOC](#table-of-contents)

demonstrate the usage of the resty.awsauth.aws_signer module

lib [lua-resty-http](https://github.com/pintsized/lua-resty-http) need to be installed

```nginx
worker_processes  1;
error_log /tmp/lua_resty_awsauth_test.error.log debug;
pid /tmp/lua_resty_awsauth_test.nginx.pid;

worker_rlimit_nofile 1024;

events {
    worker_connections 1024;
}

http {
    access_log /tmp/lua_resty_awsauth_test.access.log;

    default_type text/plain;

    # you may need to change the path depending on where the libs are installed.
    lua_package_path '/usr/local/lib/lua/?.lua;;';
    lua_package_cpath '/usr/local/lib/lua/?.so;;';

    server {
        listen 1312;

        location / {
            resolver 8.8.8.8;

            rewrite_by_lua_block {
                local aws_signer = require("resty.awsauth.aws_signer")
                local http = require("resty.http")

                local access_key = "ziw5dp1alvty9n47qksu"
                local secret_key = "V+ZTZ5u5wNvXb+KP5g0dMNzhMeWe372/yRKx4hZV"
                local end_point = "http://bscstorage.com"

                local signer, err, msg = aws_signer.new(access_key, secret_key, {default_expires = 60 * 10})
                if err ~= nil then
                    ngx.say(string.format("instantiates class aws_signer: Failed, %s %s", err, msg))
                    ngx.exit(ngx.HTTP_OK)
                end

                local httpc, err = http.new()
                if err ~= nil then
                    ngx.say(string.format("instantiates class http: Failed, %s", err))
                    ngx.exit(ngx.HTTP_OK)
                end
                httpc:set_timeout(1000 * 5)

                local file_content = "bla bla"
                local request = {
                    verb = "PUT",
                    uri = "/test-bucket/test-key",
                    args = {
                        foo = "bar",
                        foo = true,
                        foo1 = "bar1",
                    }
                    headers = {
                        Host = "bscstorage.com",
                        ['X-Amz-Acl'] = "public-read",
                        ['Content-Length'] = #file_content,
                    },
                    body = file_content,
                }

                local ctx, err, msg = signer:add_auth_v4(request, {sign_payload = true})
                if err ~= nil then
                    ngx.say(string.format("add signature: Failed, %s %s", err, msg))
                    ngx.exit(ngx.HTTP_OK)
                end

                local resp, err = httpc:request_uri(end_point .. request.uri,
                                                    {
                                                        method = request.verb,
                                                        headers = request.headers,
                                                        body = file_content,
                                                    })
                if err ~= nil then
                    ngx.say(string.format("send the request: Failed, %s", err))
                    ngx.exit(ngx.HTTP_OK)
                end

                ngx.say(string.format("the response status is: %d", resp.status))
                ngx.eof()
                ngx.exit(ngx.HTTP_OK)
            }
        }
    }
}
```

demonstrate the usage of the resty.awsauth.aws_authenticator module

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

Demo
===========

We provided simple demonstration of both signing a request and authenticating a request. It will be a good idea to try it out.

* [demo.aws_signer.README.md](demo/aws_signer/README.md) Demonstrate how to sign a request and send the signed request to an AWS S3 compatible service.

* [demo.aws_signer.demo_aws_signer.nginx.conf](demo/aws_signer/demo_aws_signer.nginx.conf) The nginx conf file for the signing demonstration.

* [demo.aws_authenticator.README.md](demo/aws_authenticator/README.md) Demonstrate how to set up a RESTful storage service and use this lua module to authenticate the request.

* [demo.aws_authenticator.demo__aws_authenticator.nginx.conf](demo/aws_authenticator/demo_aws_authenticator.nginx.conf) The nginx conf file for the authenticating demonstration.


[Back to TOC](#table-of-contents)

Description
===========

This library provides two Lua modules, one for signing request and one for authenticating request.
The signing module only support aws signatrue version 4, the authentication module support both
signature version 4 and signature version 2.

* [resty.awsauth.aws_signer](lib/resty/awsauth/aws_signer.md) The signing module used to sign a request.
* [resty.awsauth.aws_authenticator](lib/resty/awsauth/aws_authenticator.md) The authenticating module used to authenticate a request.

Please check out these Lua modules' own documentation for more details.

[Back to TOC](#table-of-contents)

Installation
============

Copy the resty directory to a location which is in the seaching path of lua require module

[Back to TOC](#table-of-contents)

Author
======

Renzhi (任稚) <zhi.ren@baishancloud.com>.

[Back to TOC](#table-of-contents)

Copyright and License
=====================

The MIT License (MIT)

Copyright (c) 2016 Renzhi (任稚) <zhi.ren@baishancloud.com>

[Back to TOC](#table-of-contents)
