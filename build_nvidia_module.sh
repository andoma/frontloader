#!/bin/bash
set -e
set -x

if [ "$NV_DRIVER_VERSION" != "" ]; then

NV_DRIVER_DIR=NVIDIA-Linux-x86_64-${NV_DRIVER_VERSION}
NV_DRIVER_BIN=${NV_DRIVER_DIR}.run

if [ ! -x .download/${NV_DRIVER_BIN} ]; then
    mkdir -p .download
    curl -L -o .download/${NV_DRIVER_BIN} http://us.download.nvidia.com/XFree86/Linux-x86_64/${NV_DRIVER_VERSION}/${NV_DRIVER_BIN}
    chmod 755 .download/${NV_DRIVER_BIN}
fi

rm -rf NVIDIA-Linux-* && .download/${NV_DRIVER_BIN} -x

make -C ${NV_DRIVER_DIR}/kernel SYSSRC=${PWD}/linux SYSOUT=${PWD}/kernel -j10

fi
