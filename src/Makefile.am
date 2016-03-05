VPATH = ../src/commons:../src

#TODO: switch installation dir to /usr/lib (like snort)

if DEBUG
AM_CPPFLAGS = -DIDMEF_DEBUG -DSTACK_DEBUG
endif


#Build the static+ shared library to be installed within libdir
lib_LTLIBRARIES = libliteidmef.la
libliteidmef_la_SOURCES = stack.c idmef_plugin.c idmef_server.c
libliteidmef_la_LDFLAGS = -version-info 0:1
include_HEADERS = idmef_plugin.h

install-data-hook:
	cd $(includedir) &&\
	mv idmef_plugin.h liteidmef.h 

pkgconfiglibdir = $(libdir)/pkgconfig
pkgconfiglib_DATA = libliteidmef-0.1.pc
