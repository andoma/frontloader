FROM ubuntu:18.04

LABEL maintainer="andoma@lookback.io"

RUN apt-get update \
    && apt-get install -y build-essential git flex bison libelf-dev bc curl file wget cpio python unzip rsync nasm kmod

WORKDIR /usr/src

ARG FRONTLOADER_GIT_VERSION
ENV FRONTLOADER_GIT_VERSION=$FRONTLOADER_GIT_VERSION

ARG NV_DRIVER_VERSION
ENV NV_DRIVER_VERSION=$NV_DRIVER_VERSION

#
# Kernel prep
#

RUN mkdir -p kernel && echo -fl-$FRONTLOADER_GIT_VERSION >kernel/localversion-frontloader
COPY kernel/.config kernel

COPY linux linux

RUN mkdir -p userland/images && touch userland/images/rootfs.cpio.xz
RUN make -C linux -j10  O=${PWD}/kernel modules

#
# Nvidia module
#

COPY build_nvidia_module.sh .
RUN ./build_nvidia_module.sh .

#
# Userland
#
COPY buildroot buildroot
COPY overlay overlay
COPY frontloader frontloader

RUN mkdir -p userland
COPY userland/.config userland

COPY finalize_root_fs.sh .
COPY prepfs.sh .

RUN make -C buildroot O=${PWD}/userland

#
# Kernel
#
RUN make -C linux -j10 O=${PWD}/kernel

#
# Bootloader
#
COPY bootloader bootloader
RUN make -C bootloader

#
# Generate output image
#
FROM scratch
ARG FRONTLOADER_GIT_VERSION
LABEL commit=$FRONTLOADER_GIT_VERSION
COPY --from=0 /usr/src/bootloader/bootloader /usr/src/kernel/arch/x86/boot/bzImage /
CMD ["/bzImage"]
