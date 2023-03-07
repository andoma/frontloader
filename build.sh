#!/bin/sh
set -e
set -x

NV_DRIVER_VERSION=525.89.02


echo "Buildind frontloader image ${FRONTLOADER_GIT_VERSION} Nvidia driver: ${NV_DRIVER_VERSION}"

if [ "$1" = "docker" ]; then

    DOCKER_BUILDKIT=1 docker build \
                   --build-arg FRONTLOADER_GIT_VERSION=$FRONTLOADER_GIT_VERSION \
                   --build-arg NV_DRIVER_VERSION=$NV_DRIVER_VERSION \
                   -t $DOCKER_IMAGE_REPOSITORY:$FRONTLOADER_GIT_VERSION \
                   -t $DOCKER_IMAGE_REPOSITORY:$FRONTLOADER_GIT_FULL \
                   -t $AWS_ECR_DOMAIN/$DOCKER_IMAGE_REPOSITORY:$FRONTLOADER_GIT_VERSION \
                   .

    LAYERNAME=$(docker image save $DOCKER_IMAGE_REPOSITORY:$FRONTLOADER_GIT_VERSION | tar -t -f - | grep /layer.tar)
    echo Extracting bootloader and kernel from layer: $LAYERNAME
    docker image save $DOCKER_IMAGE_REPOSITORY:$FRONTLOADER_GIT_VERSION | tar -x -O -f - $LAYERNAME|tar -x -O -f -  bootloader bzImage >disk.img
    exit 0
fi

export NV_DRIVER_VERSION

echo -fl-${FRONTLOADER_GIT_VERSION} >kernel/localversion-frontloader
make -C linux -j10  O=${PWD}/kernel modules
./build_nvidia_module.sh
make -C buildroot O=${PWD}/userland
make -C linux -j10  O=${PWD}/kernel
make -C bootloader
cat bootloader/bootloader kernel/arch/x86/boot/bzImage >disk.img
