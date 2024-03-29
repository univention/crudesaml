# $Id: configure.ac,v 1.18 2017/08/13 14:32:42 manu Exp $ 

AC_PREREQ([2.63])
AC_INIT([crudesaml], [1.10], [manu@netbsd.org])
AC_CONFIG_SRCDIR([saml.c])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([config.h])

AM_INIT_AUTOMAKE([foreign])

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LIBTOOL

AC_ARG_WITH(pkg-config, AS_HELP_STRING([--with-pkg-config=PATH], [set pkg-config metadata search path.]),
            PKG_CONFIG_PATH="${withval}", PKG_CONFIG_PATH="")
if test "z$PKG_CONFIG_PATH" != "z"; then
    export PKG_CONFIG_PATH
fi

PKG_CHECK_MODULES([GLIB], [glib-2.0 >= 2.4.0])
PKG_CHECK_MODULES([GOBJECT], [gobject-2.0 >= 2.4.0])
PKG_CHECK_MODULES([SASL2], [libsasl2 >= 2.1])
PKG_CHECK_MODULES([LASSO], [lasso >= 2.4])
CFLAGS="$CFLAGS $SASL2_CFLAGS $LASSO_CFLAGS"
# liblaso's include files use glib internally, so we have to explicitly link GLIB and GOBJECT
LIBS="$LIBS $GLIB_LIBS $GOBJECT_LIBS $SASL2_LIBS $LASSO_LIBS"

AC_ARG_WITH([pam],
			AS_HELP_STRING([--with-pam=DIR], [Base installation of PAM]),
		 [CFLAGS="$CFLAGS -I${with_pam}/include -DWITH_PAM"; 
		  LDFLAGS="$LDFLAGS -L${with_pam}/lib"])
AC_ARG_WITH([pamlibdir],
			AS_HELP_STRING([--with-pamlibdir=DIR], [directory for PAM modules]),
			[],
			[with_pamlibdir=/lib/security])
AC_ARG_WITH([sasllibdir],
			AS_HELP_STRING([--with-sasllibdir=DIR], [directory for SASL modules]),
			[],
			[with_sasllibdir=${libdir}/sasl2])

# Checks for libraries.
AC_CHECK_LIB([lasso], [lasso_node_new_from_xmlNode])
AC_CHECK_LIB([xml2], [xmlParseDoc])
AC_CHECK_LIB([pam], [pam_authenticate])

# Checks for header files.
AC_CHECK_HEADERS([string.h])

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.
AC_FUNC_MALLOC

AC_SUBST([pamlibdir], [$with_pamlibdir])
AC_SUBST([sasllibdir], [$with_sasllibdir])
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
