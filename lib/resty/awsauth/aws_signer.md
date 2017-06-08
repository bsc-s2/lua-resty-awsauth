Name
====

resty.awsauth.aws_signer - Lua module for signing a request with aws signature version 4.

Table of Contents
=================

* [Name](#name)
* [Synopsis](#synopsis)
* [Description](#description)
* [Methods](#methods)
    * [new](#new)
    * [add_auth_v4](#add_auth_v4)
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

[Back to TOC](#table-of-contents)

Description
===========

This module provides API to help the OpenResty/ngx_lua user porgrammers to generate a signed request,
you need to provide a lua table which represent your request(typically it contains the `verb`, `uri`,
`args`, `headers`, `body`) and your access key and your secret key, this module will add signature
to the query string or to the 'Authorization' header. this module will modify the uri and headers
you passed in, and you should send the request using the modified uri and headers.

Methods
=======

[Back to TOC](#table-of-contents)

new
---
**syntax:** `obj, err, msg = class.new(access_key, secret_key, opts)`

Instantiates an object of this class. The `class` value is returned by the call `require "resty.awsauth.aws_signer"`.

This method takes the following arguments:

* `access_key` is the access key used to sign the request.

* `secret_key` is the secret key used to sign the request.

* `opts` is the optional arguments, can be omited. You can specify the following options:

 - `region` is the region you will request to. The default is 'us-east-1'.

 - `service` is the service name. The default is 's3'.

 - `default_expires` is the default expire time of a presigned url in seconds. The default is 60.

 - `shared_dict` is the name of the lua_shared_dict shm zone, which will be used to cache the signing key.
    The default is nil, then the signing key will not be cached.

[Back to TOC](#table-of-contents)

add_auth_v4
--------
**syntax:** `ctx, err, msg = obj:add_auth_v4(request, opts)`

calculate the signature and add it to the request, this method will modify the request you passed in.

This method accepts the following arguments:

* `request` is a lua table that represent your request, it may contain the following keys:

 - `verb` is the request method, such as 'PUT', 'GET'. It can not be omited.

 - `uri` is the url encoded uri, it can contain query string depends on whether you specified `args` or not.
    It can not be omited.

 - `args` is a lua table which contain the query parameters, and it should not be url encoded.
    If you have contained query string in `uri`, you should omit this key in the `request`.
    If the request parameter does not have a value, such as '/?acl', then set the value to `true`,
    the args table will be '{acl = true}'. Also note that, the paramters specifed in `args`, will be
    encoded and add to the `uri` automatically.

 - `headers` is a lua table contains request headers, it must contain the 'Host' header. It can not be omited.

 - `body` is a string contains the request body. It can be omited if you do not want to sign
     the payload or you have set the 'X-Amz-Content-SHA256' header in `headers` in `request`.


* `opts` is a lua table contains some optional arguments, it can be omited. You can specify the following optonal arguments:

 - `query_auth` if set to `true`, the signature will be add to query string, otherwise the signature will
    be contained in 'Authorization' header.

 - `sign_payload` if set to `true`, the SHA256 of the body will be calculated if header 'X-Amz-Content-SHA256'
    is not specifed in `headers`.

 - `headers_not_to_sign` is a list of header names indicate which headers are not need to be signed.

 - `expires` is the expire time of a presigned url in seconds, it will overwrite the value of `default_expires`.

 - `signing_date` is a 8 digital date string like '20170131' used to specify a custom siging date.


The return values depend on the following cases:

* if succeed, the method will return a lua table which contains some intermidiate values used in the
    signing process, it is usefull for debuging. It may contain the following keys:

 - `string_to_sign` is the string used to calculate the signatrue.

 - `signing_key` is the key used to calculate the signatrue, which is derived from secret key.

 - `cache_hit` is boolean value to indicate whether the `signing_key` is get from the cache. If you did not
    specified a shared dict, it will always be `false`.

 - `no_memory` is boolean value to indicate whether the cache is lack of memory. If you did not
    specified a shared dict, it will always be `false`.

 - `forcible` is boolean value to indicate whether other valid items have been removed forcibly when out
    of storage in the shared memory zone. If you did not specified a shared dict, it will always be `false`.

* If something go wrong, this method will return a nil and an error code and an error message.

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
