ACLOCAL_AMFLAGS=-I m4

sasllibdir = @sasllibdir@
securitylibdir = @pamlibdir@

sasllib_LTLIBRARIES = libsaml.la
libsaml_la_SOURCES = cy2_saml.c saml.c plugin_common.c plugin_common.h saml.h
libsaml_la_CFLAGS = -I/usr/include/sasl
libsaml_la_LDFLAGS = -module -no-undefined -version-info 2:0:2 -export-symbols-regex '^sasl_'

securitylib_LTLIBRARIES = pam_saml.la
pam_saml_la_SOURCES = pam_saml.c saml.c saml.h
pam_saml_la_CFLAGS = -DNO_STATIC_MODULES
pam_saml_la_LDFLAGS = -module -no-undefined -avoid-version -shared -export-symbols-regex '^_?pam_'

man_MANS = pam_saml.5 cy2_saml.5
EXTRA_DIST = $(man_MANS)

