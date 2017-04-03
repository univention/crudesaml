#!/bin/sh

aclocal -I .
autoheader
libtoolize --automake --copy --force
autoconf
automake --add-missing --copy --foreign
