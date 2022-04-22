CROSS_COMPILE=${HOSTDIR}/usr/bin/x86_64-buildroot-linux-gnu
CC=${CROSS_COMPILE}-gcc
SYSROOT=${HOSTDIR}/usr/x86_64-buildroot-linux-gnu/sysroot
PKG_CONFIG_SYSROOT_DIR=${SYSROOT}
PKG_CONFIG_LIBDIR=${SYSROOT}/usr/lib/pkgconfig

include mk/Linux.mk
