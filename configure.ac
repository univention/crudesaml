# $Id: configure.ac,v 1.8 2009/12/08 11:19:46 manu Exp $ 

AC_PREREQ([2.63])
AC_INIT([crudesaml], [1.0], [manu@netbsd.org])
AC_CONFIG_SRCDIR([saml.c])
AM_INIT_AUTOMAKE
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LIBTOOL

AM_INIT_AUTOMAKE

AC_ARG_WITH(pkg-config, [  --with-pkg-config=PATH set pkg-config metadata search path.],
            PKG_CONFIG_PATH="${withval}", PKG_CONFIG_PATH="")
if test "z$PKG_CONFIG_PATH" != "z"; then
    export PKG_CONFIG_PATH
fi

PKG_CHECK_MODULES(CRUDESAML, glib-2.0 >= 2.4.0 gobject-2.0 >= 2.4.0 
		  libxml-2.0 xmlsec1 >= 1.2.6 xmlsec1-openssl >= 1.2.6)
CFLAGS="$CFLAGS $CRUDESAML_CFLAGS"
LIBS="$LIBS $CRUDESAML_LIBS"

AC_ARG_WITH(sasl2, [  --with-sasl2=prefix           Base installation of Cyrus SASL],
		   [CFLAGS="$CFLAGS -I${with_sasl2}/include -DWITH_SASL2"; 
		    LDFLAGS="$LDFLAGS -L${with_sasl2}/lib";
		    cyrus_sasl2_prefix="${with_sasl2}"])
AC_ARG_WITH(pam, [  --with-pam=prefix             Base installation of PAM],
		 [CFLAGS="$CFLAGS -I${with_pam}/include -DWITH_PAM"; 
		  LDFLAGS="$LDFLAGS -L${with_pam}/lib";
		  pam_prefix="${with_pam}"])
AC_ARG_WITH(lasso, [  --with-lasso[=prefix]         Base installation of Lasso],
		   [CFLAGS="$CFLAGS -I${with_lasso}/include"; 
		    LDFLAGS="$LDFLAGS -L${with_lasso}/lib"])

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([fcntl.h stdlib.h string.h strings.h syslog.h unistd.h sys/cdefs.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T
AC_HEADER_TIME

# Checks for libraries.
AC_CHECK_LIB([lasso], [lasso_node_new_from_xmlNode])
AC_CHECK_LIB([xml2], [xmlParseDoc])
AC_CHECK_LIB([xmlsec1], [xmlSecInit])
AC_CHECK_LIB([pam], [pam_authenticate])
AC_CHECK_LIB([sasl2], [sasl_client_init])
AC_CHECK_LIB([crypto], [BIO_f_base64])
AC_CHECK_LIB([z], [uncompress])

# Checks for header files.
AC_CHECK_HEADERS([string.h])

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.
AC_FUNC_MALLOC

AC_SUBST([cyrus_sasl2_prefix])
AC_SUBST([pam_prefix])
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
