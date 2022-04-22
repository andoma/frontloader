#!/bin/bash
set -e
set -x
TOPDIR=$(cd .. && pwd)


if [ "$NV_DRIVER_VERSION" != "" ]; then

    NV_DRIVER_DIR="NVIDIA-Linux-x86_64-${NV_DRIVER_VERSION}"

    NV_SRC="${TOPDIR}/${NV_DRIVER_DIR}"

    echo "Installing NVIDIA drivers from: ${NV_SRC}"

    make -C ${NV_SRC}/kernel SYSSRC=${TOPDIR}/linux SYSOUT=${TOPDIR}/kernel  modules_install INSTALL_MOD_PATH="$1" V=1

    O_LIB="$1/usr/lib"

    NV_LIBS="libcuda.so libnvidia-encode.so libnvcuvid.so libnvidia-ml.so"

    for LIB in ${NV_LIBS}; do
        cp ${NV_SRC}/${LIB}.${NV_DRIVER_VERSION} ${O_LIB}/
        ln -s ${LIB}.${NV_DRIVER_VERSION} ${O_LIB}/${LIB}.1
    done
    cp ${NV_SRC}/nvidia-smi "$1/usr/bin/"
    cp ${NV_SRC}/nvidia-modprobe "$1/usr/bin/"

fi
