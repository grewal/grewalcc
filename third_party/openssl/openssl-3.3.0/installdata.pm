package OpenSSL::safe::installdata;

use strict;
use warnings;
use Exporter;
our @ISA = qw(Exporter);
our @EXPORT = qw($PREFIX
                  $BINDIR $BINDIR_REL
                  $LIBDIR $LIBDIR_REL
                  $INCLUDEDIR $INCLUDEDIR_REL
                  $APPLINKDIR $APPLINKDIR_REL
                  $ENGINESDIR $ENGINESDIR_REL
                  $MODULESDIR $MODULESDIR_REL
                  $PKGCONFIGDIR $PKGCONFIGDIR_REL
                  $CMAKECONFIGDIR $CMAKECONFIGDIR_REL
                  $VERSION @LDLIBS);

our $PREFIX             = '/home/monty/src/grewalcc/third_party/nginx/mainline/nginx-1.25.4/../../../openssl/openssl-3.3.0/.openssl';
our $BINDIR             = '/home/monty/src/grewalcc/third_party/nginx/mainline/nginx-1.25.4/../../../openssl/openssl-3.3.0/.openssl/bin';
our $BINDIR_REL         = 'bin';
our $LIBDIR             = '/home/monty/src/grewalcc/third_party/nginx/mainline/nginx-1.25.4/../../../openssl/openssl-3.3.0/.openssl/lib64';
our $LIBDIR_REL         = 'lib64';
our $INCLUDEDIR         = '/home/monty/src/grewalcc/third_party/nginx/mainline/nginx-1.25.4/../../../openssl/openssl-3.3.0/.openssl/include';
our $INCLUDEDIR_REL     = 'include';
our $APPLINKDIR         = '/home/monty/src/grewalcc/third_party/nginx/mainline/nginx-1.25.4/../../../openssl/openssl-3.3.0/.openssl/include/openssl';
our $APPLINKDIR_REL     = 'include/openssl';
our $ENGINESDIR         = '/home/monty/src/grewalcc/third_party/nginx/mainline/nginx-1.25.4/../../../openssl/openssl-3.3.0//.openssl/lib64/engines-3';
our $ENGINESDIR_REL     = 'lib64/engines-3';
our $MODULESDIR         = '/home/monty/src/grewalcc/third_party/nginx/mainline/nginx-1.25.4/../../../openssl/openssl-3.3.0//.openssl/lib64/ossl-modules';
our $MODULESDIR_REL     = 'lib64/ossl-modules';
our $PKGCONFIGDIR       = '/home/monty/src/grewalcc/third_party/nginx/mainline/nginx-1.25.4/../../../openssl/openssl-3.3.0//.openssl/lib64/pkgconfig';
our $PKGCONFIGDIR_REL   = 'lib64/pkgconfig';
our $CMAKECONFIGDIR     = '/home/monty/src/grewalcc/third_party/nginx/mainline/nginx-1.25.4/../../../openssl/openssl-3.3.0//.openssl/lib64/cmake/OpenSSL';
our $CMAKECONFIGDIR_REL = 'lib64/cmake/OpenSSL';
our $VERSION            = '3.3.0';
our @LDLIBS             =
    # Unix and Windows use space separation, VMS uses comma separation
    split(/ +| *, */, '-ldl ');

1;
