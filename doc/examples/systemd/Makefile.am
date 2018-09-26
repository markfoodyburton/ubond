# UBOND
# (c) 2015 Laurent Coustet <ed@zehome.com>

TEMPLATES =

## systemd service file
if HAVE_SYSTEMDSYSTEMUNITDIR
systemdsystemunit_DATA = ubond.service ubond@.service
TEMPLATES += $(systemdsystemunit_DATA)
endif

if HAVE_SYSTEMDSYSTEMGENERATORDIR
systemdsystemgenerator_SCRIPTS = ubond-generator
TEMPLATES += $(systemdsystemgenerator_SCRIPTS)
endif

if HAVE_SYSTEMDTMPFILESDIR
systemdtmpfiles_DATA = ubond.conf
TEMPLATES += $(systemdtmpfiles_DATA)
endif

EXTRA_DIST = ubond.service.in ubond@.service.in ubond-generator.in ubond.conf.in

ubond.service: ubond.service.in
ubond@.service: ubond@.service.in
ubond-generator: ubond-generator.in
ubond.conf: ubond.conf.in

CLEANFILES  = $(TEMPLATES)

include $(top_srcdir)/template.am
