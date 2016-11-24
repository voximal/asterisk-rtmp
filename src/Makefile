#
# Asterisk -- A telephony toolkit for Linux.
# 
# Makefile for channel drivers
#
# Copyright (C) 1999-2006, Digium, Inc.
#
# This program is free software, distributed under the terms of
# the GNU General Public License
#

ASTTOPDIR=$(ASTERISKDIR)
FFMPEGDIR=$(FFMPEGOLDDIR)
ASTMACDIR=$(ASTERISKMACROSDIR)/include

include ${ASTTOPDIR}/menuselect.makeopts ${ASTTOPDIR}/menuselect.makedeps

INSTALL_PREFIX := /usr
INSTALL_MODULES_DIR := $(INSTALL_PREFIX)/lib/asterisk/modules
MODULES_DIR := ${INSTALL_MODULES_DIR}

#LIBS := -L$(FFMPEGDIR)/libavcodec -lavcodec -lssl -lcrypto -L$(LIBGEOIPDIR)/.libs -lGeoIP -ljpeg
LIBS := -lssl -lcrypto -L$(LIBGEOIPDIR)/.libs -lGeoIP
RPATH := -Wl,-rpath=/usr/lib/asteriskrtmp:/usr/lib/openvxi

MENUSELECT_CATEGORY=CHANNELS
MENUSELECT_DESCRIPTION=Channel Drivers

ALL_C_MODS:=$(patsubst %.c,%,$(wildcard chan_*.c))
ALL_CC_MODS:=$(patsubst %.cc,%,$(wildcard chan_*.cc))

C_MODS:=$(filter-out $(MENUSELECT_CHANNELS),$(ALL_C_MODS))
CC_MODS:=$(filter-out $(MENUSELECT_CHANNELS),$(ALL_CC_MODS))

LOADABLE_MODS:=$(C_MODS) $(CC_MODS)

ifneq ($(findstring channels,$(MENUSELECT_EMBED)),)
  EMBEDDED_MODS:=$(LOADABLE_MODS)
  LOADABLE_MODS:=
endif

RTMPOBJS=chan_rtmp.o flvtools.o
SHAREDOS=chan_rtmp.so


CFLAGS += -ggdb -march=$(LINUX_BUILD) -fPIC -DAST_MODULE=\"chan_rtmp\" -pipe -Wall -Wmissing-prototypes -Wmissing-declarations $(DEBUG) $(INCLUDE) -D_REENTRANT -D_GNU_SOURCE -Dulex
RTMPCFLAGS = -I./ -I$(ASTTOPDIR)/include -I$(ASTMACDIR) -I$(LIBGEOIPDIR)

# Options
ifneq ($(FFMPEGDIR), "")
#LIBS += -L$(FFMPEGDIR)/libavcodec -lavcodec
#RTMPCFLAGS += -DRTMP_FFMPEG -I$(FFMPEGDIR)
endif

all: _all

include $(ASTTOPDIR)/Makefile.moddir_rules

clean::
	rm -f $(addprefix $(RTMPOBJS).,$(ALL_C_MODS) $(ALL_CC_MODS))

chan_rtmp.o: ASTCFLAGS+=$(RTMPCFLAGS) $(CFLAGS)

flvtools.o: ASTCFLAGS+=$(RTMPCFLAGS) $(CFLAGS)

chan_rtmp.so : $(RTMPOBJS)
	$(CC) -pg -shared -Xlinker -x -o $@ $(RTMPOBJS) $(LIBS) $(RPATH)

$(if $(filter chan_rtmp,$(EMBEDDED_MODS)),modules.link,chan_rtmp.so): ASTCFLAGS+=$(RTMPCFLAGS) $(CFLAGS)
$(if $(filter chan_rtmp,$(EMBEDDED_MODS)),modules.link,chan_rtmp.so): chan_rtmp.o

install2: all
	for x in $(SHAREDOS); do $(INSTALL) -m 755 $$x $(INSTALL_MODULES_DIR) ; done
