# UBOND
# (c) 2015 Laurent Coustet <ed@zehome.com>

SUBDIRS = systemd
if INSTALL_EXAMPLES
dist_doc_DATA = ubond.conf \
    ubond_updown.sh ubond.init.d ubond.default ubond.rc
else
nodist_doc_DATA = ubond.conf ubond_updown.sh ubond.init.d ubond.rc
endif

ubond.conf: ubond.conf.in
ubond_updown.sh: ubond_updown.sh.in
ubond.init.d: ubond.init.d.in
ubond.rc: ubond.rc.in

TEMPLATES   = ubond.conf ubond_updown.sh ubond.init.d ubond.rc
EXTRA_DIST  = ubond.conf.in ubond_updown.sh.in ubond.init.d.in ubond.rc.in
CLEANFILES  = $(TEMPLATES)

include $(top_srcdir)/template.am
