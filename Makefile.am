ACLOCAL_AMFLAGS=-I m4

sasllibdir = @cyrus_sasl2_prefix@/lib/sasl2
securitylibdir = $(DESTDIR)$(libdir)/security

sasllib_LTLIBRARIES = libsaml.la
libsaml_la_SOURCES = cy2_saml.c saml.c plugin_common.c plugin_common.h saml.h
libsaml_la_LDFLAGS = -lsasl2 -llasso -module -version-info 2:0:2
libsaml_la_CFLAGS = -I/usr/include/sasl

securitylib_LTLIBRARIES = pam_saml.la
pam_saml_la_SOURCES = pam_saml.c saml.c saml.h
pam_saml_la_CFLAGS = -DNO_STATIC_MODULES
pam_saml_la_LDFLAGS = -lsasl2 -module -version-info 2:0:2

man_MANS = pam_saml.5 cy2_saml.5
EXTRA_DIST = $(man_MANS)

