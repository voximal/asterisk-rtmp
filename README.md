chan_rtmp
=========

---
A RTMP Channel for Asterisk

* Writen in C using asterisk-macros.
* Asterisk 1.6 to Asterisk 11.
* This module supports realtime and static peers.


Installation
------------

```sh
export ASTERISKMACROSDIR=[Asterisk macros Git Voximal directory]
export ASTERISKDIR=[Asterisk sources directory]
export LINUX_BUILD=[x86-64 or i686 or armv6l]
export LIBGEOIPDIR=[GeoIP sources directory]/libGeoIP/

git clone https://github.com/voximal/asterisk-rtmp chan_rtmp
cd chan_rtmp/src
make
make install
```

Client
------

The client over FlashPlayer allows to set differents skins.

An Android SDK for smartphone/webtv is available to create video call applications.


Demonstration
-------------

default : http://rtmp.ulex.fr/webphone

more looks : http://rtmp.ulex.fr/webphone/look.html


Contact 
-------

Contact us with the Ulex web site : http://www.ulex.fr
