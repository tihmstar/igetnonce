AM_CFLAGS = $(libirecovery_CFLAGS) $(libimobiledevice_CFLAGS) $(libusbmuxd_CFLAGS) $(openssl_CFLAGS)
AM_LDFLAGS = $(libirecovery_LIBS) $(libimobiledevice_LIBS) $(libusbmuxd_LIBS) $(openssl_LIBS)

bin_PROGRAMS	= igetnonce
igetnonce_CFLAGS = $(AM_CFLAGS)
igetnonce_LDADD = $(AM_LDFLAGS)
igetnonce_SOURCES	= common.c dfu.c idevicerestore.c normal.c recovery.c main.c

