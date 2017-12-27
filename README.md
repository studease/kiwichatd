# kiwichatd

> [[domain] http://studease.cn](http://studease.cn/kiwichatd.html)

> [[source] https://github.com/studease/kiwichatd](https://github.com/studease/kiwichatd)

> [[中文] http://blog.csdn.net/icysky1989/article/details/52138527](http://blog.csdn.net/icysky1989/article/details/52138527)

> 公众号：STUDEASE

> QQ群：528109813

This is a high-concurrency websocket chat server.


## Description
--------------

For the Enterprise Edition, supply an interface to return a JSON object formatted as /data/userinfo.json.

While a client connecting to upgrade protocol, it sends an identify upstream request, carrying channel and token params, 
to get the user info, which will decide whether the operation will be satisfied.

The Preview Edition is more like a stand-alone server. The user info, includes name, icon, role, and channel state could be
present in params. However, this is not safe.


## Build
--------

To build kiwichatd, you need CMake 3.5 and or above, and OpenSSL installed. Then run:

```
cmake .
make
```


## Run
------

```
sudo ./start.sh
```


## Linux Static Builds
----------------------

#### 32-bit and 64-bit for kernel 3.9 and above

> x86: [kiwichatd-x86-latest-static.zip](http://studease.cn/static/kiwichatd-x86-latest-static.zip)


## Client
---------

[chatease.js https://github.com/studease/chatease](https://github.com/studease/chatease)


## License
----------

MIT
