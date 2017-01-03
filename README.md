chan_rtmp
=========

---
A RTMP Channel for Asterisk

* Writen in C using asterisk-wrapper.
* Asterisk 1.6 to Asterisk 11.
* This module supports realtime and static peers.


Installation
------------

```sh
export ASTERISKMACROSDIR=[Asterisk macros Git Voximal directory]
export ASTERISKDIR=[Asterisk source directory]
export LINUX_BUILD=[x86-64 or i686 or armv6l]

git clone [git-repo-url] chan_rtmp
cd chan_rtmp
make
make install
```

Client
------

The client allows to set differents skins.


Demonstration
-------------

default :http://rtmp.ulex.fr/webphone

more looks :http://rtmp.ulex.fr/webphone/look.html
