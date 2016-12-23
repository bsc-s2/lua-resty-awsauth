Name
====

demo of signing a request and send the request to an AWS S3 compatible service.

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

In this demonstration, we will request to an AWS S3 compatible service('http://bscstorage.com').
We will use a public account to sign the request, you can use your own accout by change the access
key and secret key in file 'demo_aws_signer.nginx.conf' to your own keys. We will demonstrate how to
ceate a bucket, upload a file to bucket, download a file, get the ACL of a file, delete a file,
delete a bucket. You can get more details by have a look at file 'demo_aws_signer.nginx.conf'.

Requirement
===========

Directory '/tmp' must exists.
[lua-resty-http](https://github.com/pintsized/lua-resty-http) must be installed.

Usage
=====

note: all the following command are excuted in the root directory of this lib.

* 1. cp file 'demo_aws_signer.nginx.conf' to '/root'(or whatever path you like, here is for simpilicity).

```shell
    cp demo/aws_signer/demo_aws_signer.nginx.conf /root
```

* 2. start the nginx server.

the nginx server will listen on port '1312', if this port is already in use, you can change it by modify
file 'demo_aws_signer.nginx.conf'.

```shell
    nginx -c /root/demo_aws_signer.nginx.conf
```

* 3. send request to the nginx server.

```shell
    curl -v '127.0.0.1:1312'
```

the response will be something like:

```shell
* About to connect() to 127.0.0.1 port 1312 (#0)
*   Trying 127.0.0.1...
* Connected to 127.0.0.1 (127.0.0.1) port 1312 (#0)
> GET / HTTP/1.1
> User-Agent: curl/7.29.0
> Host: 127.0.0.1:1312
> Accept: */*
>
< HTTP/1.1 200 OK
< Server: openresty/1.9.7.4
< Date: Fri, 23 Dec 2016 07:16:55 GMT
< Content-Type: text/plain
< Transfer-Encoding: chunked
< Connection: keep-alive
<
step 1, instantiates class aws_signer: OK
step 2, instantiates class http: OK
step 3.1, prepare the request: OK
step 3.2, add signature: OK
step 3.3, send the request: OK
step 3.4, show response status: OK 200
step 4.1, prepare the request: OK
step 4.2, add signature: OK
step 4.3, send the request: OK
step 4.4, show response status: OK, status is 200
step 5.1, prepare the request: OK
step 5.2, add signature: OK
step 5.3, send the request: OK
step 5.4, show response: OK, status is 200, file content is: bla bla
step 6.1, prepare the request: OK
step 6.2, add signature: OK
step 6.3, send the request: OK
step 6.4, show response status: OK, status is 200
step 7.1, prepare the request: OK
step 7.2, add signature: OK
step 7.3, send the request: OK
step 7.4, show response status: OK, status is 200
step 8.1, prepare the request: OK
step 8.2, add signature: OK
step 8.3, send the request: OK
step 8.4, show response status: OK, status is 200
* Connection #0 to host 127.0.0.1 left intact
```

[Back to TOC](#table-of-contents)

Author
======

Renzhi (任稚) <zhi.ren@baishancloud.com>.

[Back to TOC](#table-of-contents)

Copyright and License
=====================

This module is licensed under the BSD license.

Copyright (C) 2015-2017, by Yichun "agentzh" Zhang, OpenResty Inc.

All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

[Back to TOC](#table-of-contents)
