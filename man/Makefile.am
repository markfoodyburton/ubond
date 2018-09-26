dist_man_MANS = ubond.1 ubond.conf.5
noinst_man_MANS = ubond.1.ronn ubond.conf.5.ronn


if HAVE_RONN
ubond.1:
	ronn --pipe < ubond.1.ronn > ubond.1 || rm ubond.1 2>/dev/null

ubond.conf.5:
	ronn --pipe < ubond.conf.5.ronn > ubond.conf.5 || rm ubond.conf.5 2>/dev/null
endif
