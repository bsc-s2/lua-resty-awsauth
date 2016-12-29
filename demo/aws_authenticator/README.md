Name
====

demo of implementing a simple RESTful storage service, and authenticate the request.

Table of Contents
=================

* [Name](#name)
* [Introduction](#introduction)
* [Requirement](#requirement)
* [Usage](#usage)
* [Author](#author)
* [Copyright and License](#copyright-and-license)

Introduction
============

[Back to TOC](#table-of-contents)

In this demonstration, we will impliment a simple RESTful storage service, let users to creat
bucket, and upload files to bucket. In order to access this service, user have to sign the
request. When we receive a request from user, we will authenticate the request with this
Lua module. If the authentication failed, reject the request. This demonstration service also
support browser-based uploads using POST.

For simplicity, we will save user data in nginx shared dict, in a lua table. The following structure
demonstrate how data are organized.

```
{
    renzhi = {
        bucket1 = {
            file1 = 'bla bla',
            file2 = 'this is file content',
        },
        test-bucket = {
        }
    }

    user2 = {
        bucket3 = {
            file1 = 'foo bar'
        }
        bucket-foo = {
            test-key = 'bla bla'
        }
    }

    -- ...
}
```

For more details, take a look at file 'demo_aws_authenticator.nginx.conf'.

When you send request to this simple RESTful storage service, you need to sign the request.
For convenience, we provid two script file 'get_presigned_url.py' and 'calc_signature.py',
they will help you to generate a presigned url. In order to use it, you need to install `boto3`
first, use the following command. The following demonstration will show you how to use them.

```shell
    pip install boto3
```

[Back to TOC](#table-of-contents)

Requirement
===========

Directory '/tmp' must exists.

Usage
=====

[Back to TOC](#table-of-contents)

note: all the following commands are excuted in the root directory of this lib.

* 1. cp 'demo_aws_authenticator.nginx.conf' to '/root'(or whatever path you like, here is for simpilicity).

```shell
    cp demo/aws_authenticator/demo_aws_authenticator.nginx.conf /root
```

* 2. start the nginx

the nginx server will listen on port '1313', if this port is already in use, you can change it by modify
file 'demo_aws_authenticator.nginx.conf'.

```shell
    nginx -c /root/demo_aws_authenticator.nginx.conf
```

* 3. test anonymous access.

```shell
    curl -v '127.0.0.1:1313'
```

the response will be something like:

```shell
* About to connect() to 127.0.0.1 port 1313 (#0)
*   Trying 127.0.0.1...
* Connected to 127.0.0.1 (127.0.0.1) port 1313 (#0)
> GET / HTTP/1.1
> User-Agent: curl/7.29.0
> Host: 127.0.0.1:1313
> Accept: */*
>
< HTTP/1.1 403 Forbidden
< Server: openresty/1.9.7.4
< Date: Fri, 23 Dec 2016 08:00:20 GMT
< Content-Type: text/plain
< Transfer-Encoding: chunked
< Connection: keep-alive
<
this service does not allow anonymous access
* Connection #0 to host 127.0.0.1 left intact
```

* 4. test create a bucket.

```shell
    url=`python get_presigned_url.py create_bucket test-bucket`
    curl -v $url -X PUT
```

the response will be something like:

```shell
* About to connect() to 127.0.0.1 port 1313 (#0)
*   Trying 127.0.0.1...
* Connected to 127.0.0.1 (127.0.0.1) port 1313 (#0)
> PUT /test-bucket?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Expires=60000&X-Amz-Credential=renzhi_access_key%2F20161223%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-SignedHeaders=host&X-Amz-Date=20161223T083851Z&X-Amz-Signature=0bea536ff718cae9d8977bc27eb7cb9815d91fddeeb4e4e2080afbcda13395f3 HTTP/1.1
> User-Agent: curl/7.29.0
> Host: 127.0.0.1:1313
> Accept: */*
>
< HTTP/1.1 200 OK
< Server: openresty/1.9.7.4
< Date: Fri, 23 Dec 2016 08:39:04 GMT
< Content-Type: text/plain
< Transfer-Encoding: chunked
< Connection: keep-alive
<
* Connection #0 to host 127.0.0.1 left intact
```

* 5. test list buckets.

```shell
    url=`python get_presigned_url.py list_buckets`
    curl -v $url
```

the response will be something like:

```shell
* About to connect() to 127.0.0.1 port 1313 (#0)
*   Trying 127.0.0.1...
* Connected to 127.0.0.1 (127.0.0.1) port 1313 (#0)
> GET /?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Expires=60000&X-Amz-Credential=renzhi_access_key%2F20161223%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-SignedHeaders=host&X-Amz-Date=20161223T084309Z&X-Amz-Signature=23e4680e44145d357a76a0c29da4c3451adca6a1abeb6cc9954fc73d7933b98f HTTP/1.1
> User-Agent: curl/7.29.0
> Host: 127.0.0.1:1313
> Accept: */*
>
< HTTP/1.1 200 OK
< Server: openresty/1.9.7.4
< Date: Fri, 23 Dec 2016 08:43:11 GMT
< Content-Type: text/plain
< Transfer-Encoding: chunked
< Connection: keep-alive
<
you have the following 1 buckets:
bucket name: test-bucket, number of files: 0
* Connection #0 to host 127.0.0.1 left intact
```

* 6. test upload a file to bucket.

```shell
    url=`python get_presigned_url.py put_object test-bucket test-key`
    curl -v $url -X PUT -d 'bla bla'
```

the response will be something like:

```shell
* About to connect() to 127.0.0.1 port 1313 (#0)
*   Trying 127.0.0.1...
* Connected to 127.0.0.1 (127.0.0.1) port 1313 (#0)
> PUT /test-bucket/test-key?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Expires=60000&X-Amz-Credential=renzhi_access_key%2F20161223%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-SignedHeaders=host&X-Amz-Date=20161223T085303Z&X-Amz-Signature=3343a4129bcd339d1a731c294f50ca98c9f56f4bab66e93ed8a085a59d5de232 HTTP/1.1
> User-Agent: curl/7.29.0
> Host: 127.0.0.1:1313
> Accept: */*
> Content-Length: 7
> Content-Type: application/x-www-form-urlencoded
>
* upload completely sent off: 7 out of 7 bytes
< HTTP/1.1 200 OK
< Server: openresty/1.9.7.4
< Date: Fri, 23 Dec 2016 08:53:14 GMT
< Content-Type: text/plain
< Transfer-Encoding: chunked
< Connection: keep-alive
<
* Connection #0 to host 127.0.0.1 left intact
```

* 7. test list objects in a bucket.

```shell
    url=`python get_presigned_url.py list_objects test-bucket`
    curl -v $url
```

the response will be something like:

```shell
* About to connect() to 127.0.0.1 port 1313 (#0)
*   Trying 127.0.0.1...
* Connected to 127.0.0.1 (127.0.0.1) port 1313 (#0)
> GET /test-bucket?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Expires=6000&X-Amz-Credential=renzhi_access_key%2F20161223%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-SignedHeaders=host&X-Amz-Date=20161223T085521Z&X-Amz-Signature=7d668ec91438209a960d532017a74193a2a62997d1b42a4258e30b5a9877fc36 HTTP/1.1
> User-Agent: curl/7.29.0
> Host: 127.0.0.1:1313
> Accept: */*
>
< HTTP/1.1 200 OK
< Server: openresty/1.9.7.4
< Date: Fri, 23 Dec 2016 08:55:28 GMT
< Content-Type: text/plain
< Transfer-Encoding: chunked
< Connection: keep-alive
<
bucket: test-bucket, contains the following 1 files:
file name: test-key, file size: 7
* Connection #0 to host 127.0.0.1 left intact
```

* 8. test download a file.

```shell
    url=`python get_presigned_url.py get_object test-bucket test-key`
    curl -v $url
```

the response will be something like:

```shell
* About to connect() to 127.0.0.1 port 1313 (#0)
*   Trying 127.0.0.1...
* Connected to 127.0.0.1 (127.0.0.1) port 1313 (#0)
> GET /test-bucket/test-key?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Expires=60000&X-Amz-Credential=renzhi_access_key%2F20161223%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-SignedHeaders=host&X-Amz-Date=20161223T085715Z&X-Amz-Signature=2e50fa7d6ecd813bbbcab57c0cdad2815c9ffd0b570e116578f2370efa64f246 HTTP/1.1
> User-Agent: curl/7.29.0
> Host: 127.0.0.1:1313
> Accept: */*
>
< HTTP/1.1 200 OK
< Server: openresty/1.9.7.4
< Date: Fri, 23 Dec 2016 08:57:23 GMT
< Content-Type: text/plain
< Transfer-Encoding: chunked
< Connection: keep-alive
<
bla bla
* Connection #0 to host 127.0.0.1 left intact
```

* 9. test delete a file.

```shell
    url=`python get_presigned_url.py delete_object test-bucket test-key`
    curl -v $url -X DELETE
```

the response will be something like:

```shell
* About to connect() to 127.0.0.1 port 1313 (#0)
*   Trying 127.0.0.1...
* Connected to 127.0.0.1 (127.0.0.1) port 1313 (#0)
> DELETE /test-bucket/test-key?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Expires=60000&X-Amz-Credential=renzhi_access_key%2F20161223%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-SignedHeaders=host&X-Amz-Date=20161223T085904Z&X-Amz-Signature=e069c508ae7d3a8c8e71ad3bb8313d58f575bcaf9a2f0202cf01ecd2e682878c HTTP/1.1
> User-Agent: curl/7.29.0
> Host: 127.0.0.1:1313
> Accept: */*
>
< HTTP/1.1 204 No Content
< Server: openresty/1.9.7.4
< Date: Fri, 23 Dec 2016 08:59:14 GMT
< Connection: keep-alive
<
* Connection #0 to host 127.0.0.1 left intact
```

* 10. test browser-based uploads using POST.
```shell
    policy='{"expiration": "2037-11-01T12:00:00.000Z", "conditions": [{"acl": "public-read" }, {"bucket": "test-bucket" }, ["starts-with", "$key", "user/renzhi/"], ["starts-with", "$X-Amz-Date", "20"],{"X-Amz-Algorithm": "AWS4-HMAC-SHA256"}, ["starts-with", "$X-Amz-Credential", "access_key"], ]}'
    policy_base64=`echo -n "$policy" | base64`

    access_key="renzhi_access_key"
    secret_key="renzhi_secret_key"
    signing_date=`date "+%Y%m%d"`
    region="us-east-1"
    service="s3"
    request_date=`date "+%Y%m%dT%H%M%SZ"`

    signature=`python calc_signature.py "$policy_base64" "$secret_key" "$signing_date" "$region" "$service"`

    curl -v -F policy="$policy_base64" -F acl="public-read"  -F X-Amz-Credential="$access_key/$signing_date/$region/$service/aws4_request" -F X-Amz-Algorithm="AWS4-HMAC-SHA256" -F X-Amz-Date="$request_date" -F X-Amz-Signature="$signature" -F Key="user/renzhi/test-key" -F file="bla bla" '127.0.0.1:1313' -H 'Host: test-bucket.renzhi.com'
```

```shell
* About to connect() to 127.0.0.1 port 1313 (#0)
*   Trying 127.0.0.1...
* Connected to 127.0.0.1 (127.0.0.1) port 1313 (#0)
> POST / HTTP/1.1
> User-Agent: curl/7.29.0
> Accept: */*
> Host: test-bucket.renzhi.com
> Content-Length: 1400
> Expect: 100-continue
> Content-Type: multipart/form-data; boundary=----------------------------007fd77ba59a
>
< HTTP/1.1 100 Continue
< HTTP/1.1 200 OK
< Server: openresty/1.9.7.4
< Date: Tue, 27 Dec 2016 03:12:16 GMT
< Content-Type: text/plain
< Transfer-Encoding: chunked
< Connection: keep-alive
<
* Connection #0 to host 127.0.0.1 left intact
```

* 11. test delete a bucket.

```shell
    url=`python get_presigned_url.py delete_bucket test-bucket`
    curl -v $url -X DELETE
```

the response will be something like:

```shell
* About to connect() to 127.0.0.1 port 1313 (#0)
*   Trying 127.0.0.1...
* Connected to 127.0.0.1 (127.0.0.1) port 1313 (#0)
> DELETE /test-bucket?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Expires=60000&X-Amz-Credential=renzhi_access_key%2F20161223%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-SignedHeaders=host&X-Amz-Date=20161223T090047Z&X-Amz-Signature=9c2e7077ac98a219d990120f7dc55ef5b9cddc9c2827a5a42c0737421b6655d6 HTTP/1.1
> User-Agent: curl/7.29.0
> Host: 127.0.0.1:1313
> Accept: */*
>
< HTTP/1.1 204 No Content
< Server: openresty/1.9.7.4
< Date: Fri, 23 Dec 2016 09:04:07 GMT
< Connection: keep-alive
<
* Connection #0 to host 127.0.0.1 left intact
```

* 12. test invalid signature.

```shell
    url=`python get_presigned_url.py list_buckets`
    curl -v ${url}x
```

the response will be something like:

```shell
* About to connect() to 127.0.0.1 port 1313 (#0)
*   Trying 127.0.0.1...
* Connected to 127.0.0.1 (127.0.0.1) port 1313 (#0)
> GET /?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Expires=60000&X-Amz-Credential=renzhi_access_key%2F20161223%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-SignedHeaders=host&X-Amz-Date=20161223T093711Z&X-Amz-Signature=def2058f797a7ca9b4a7f30efc3be6dcc020d868e6e0e56f400d1cff9d00bfedx HTTP/1.1
> User-Agent: curl/7.29.0
> Host: 127.0.0.1:1313
> Accept: */*
>
< HTTP/1.1 403 Forbidden
< Server: openresty/1.9.7.4
< Date: Fri, 23 Dec 2016 09:38:43 GMT
< Content-Type: text/plain
< Transfer-Encoding: chunked
< Connection: keep-alive
<
authenticate failed: SignatureDoesNotMatch, string to sign:AWS4-HMAC-SHA256
20161223T093711Z
20161223/us-east-1/s3/aws4_request
ec14a3fc086fb7d07c8ee968598355a2392cfa634bb4c3ecb09382cac3a2c3dc
canonical_request:GET
/
X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=renzhi_access_key%2F20161223%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20161223T093711Z&X-Amz-Expires=60000&X-Amz-SignedHeaders=host
host:127.0.0.1:1313

host
UNSIGNED-PAYLOAD
* Connection #0 to host 127.0.0.1 left intact
```

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
