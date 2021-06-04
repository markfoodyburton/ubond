#
# UBOND
# (c) 2015 Laurent Coustet <ed@zehome.com>

ACLOCAL_AMFLAGS = -I $(top_srcdir)/m4
AUTOMAKE_OPTIONS = foreign

sbin_PROGRAMS = ubond
ubond_SOURCES = \
    includes.h defines.h \
    pkt.h pkt.c \
    configlib.c configlib.h \
    config.c \
    tool.c tool.h \
    privsep.c privsep_fdpass.c privsep.h \
    log.c log.h \
    reorder.h reorder.c \
    timestamp.h timestamp.c \
    tuntap_generic.c tuntap_generic.h \
    ubond.c ubond.h

# There are better ways to do that, using a "compat" library
# and using AC_REPLACE_FUNCS.
if !HAVE_STRNVIS
ubond_SOURCES += vis.c vis.h
endif
if !HAVE_CLOSEFROM
ubond_SOURCES += closefrom.c
endif
if !HAVE_SETPROCTITLE
ubond_SOURCES += setproctitle.c setproctitle.h
endif
if !HAVE_STRLCAT
ubond_SOURCES += strlcat.c
endif
if !HAVE_STRLCPY
ubond_SOURCES += strlcpy.c
endif

if LINUX
ubond_SOURCES += tuntap_linux.c systemd.c systemd.h
endif

if BSD
ubond_SOURCES += tuntap_bsd.c
endif

if DARWIN
ubond_SOURCES += tuntap_darwin.c
endif

if ENABLE_CONTROL
ubond_SOURCES += control.c control.h
endif

# Always include thoses files for distribution
EXTRA_DIST = \
    closefrom.c \
    setproctitle.c setproctitle.h \
    strlcat.c \
    strlcpy.c \
    vis.c vis.h \
    tuntap_linux.c \
    tuntap_bsd.c \
    systemd.c systemd.h \
    control.c control.h

ubond_LDADD=-lm $(libsodium_LIBS) $(libev_LIBS)
ubond_CFLAGS=$(CFLAGS) $(libsodium_CFLAGS) $(libev_CFLAGS)

if HAVE_FILTERS
ubond_SOURCES += filters.c
ubond_LDADD += $(libpcap_LIBS)
ubond_CFLAGS += $(libpcap_CFLAGS)
endif
