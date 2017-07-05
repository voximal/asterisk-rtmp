chan_rtmp
=========

---
The RTMP Asterisk module allows to place audio (and video) calls from a web browser using the FlashPlayer from Adobe(R).

We offer a free FlashPhone to connect to the Asterisk using the RTMP module.

Main features
-------------

* Writen in C using asterisk-macros.
* Asterisk 1.6 to Asterisk 11.(help requested to port it to Asterisk 13/14)
* This module supports realtime and static peers.
* Text/Chat features
* Audio and Video
* Geo localisation (with IP)
* Works with Vconference (Video / Switch module), Transcode (video transcoder)
* configuration file (rtmp.conf)
* realtime configuration
* Codecs supported : Speex, a/ulaw , PCM 16 bits, Video Sorenson

 
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


Demo
----

- default : http://rtmp.ulex.fr/webphone

- more looks : http://rtmp.ulex.fr/webphone/look.html



Contact 
-------

Contact us with the Ulex web site : http://www.ulex.fr
