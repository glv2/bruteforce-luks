AUTOMAKE_OPTIONS = subdir-objects dist-lzip
SUBDIRS = tests
bin_PROGRAMS = bruteforce-luks
bruteforce_luks_SOURCES = src/bruteforce-luks.c src/version.h
dist_man_MANS = doc/bruteforce-luks.1
EXTRA_DIST = \
	tests/crack-volume1.sh \
	tests/crack-volume2.sh \
	tests/crack-volume3.sh \
	tests/dict.txt \
	tests/volume1-header \
	tests/volume2-header \
	tests/volume3-header
