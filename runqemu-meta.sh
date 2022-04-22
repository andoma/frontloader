#!/bin/bash

truncate -s10g extradisk.raw

qemu-system-x86_64 \
    -nographic -serial mon:stdio \
    -m size=8192 \
    -netdev user,id=mynet0,net=192.168.76.0/24,dhcpstart=192.168.76.9 \
    -object rng-random,filename=/dev/urandom,id=rng0 \
    -drive file=extradisk.raw,format=raw,if=virtio \
    -device virtio-rng-pci,rng=rng0 \
    -device virtio-net-pci,netdev=mynet0 \
    -kernel kernel/arch/x86/boot/bzImage \
    -append "ip=dhcp console=ttyS0 FL_META_CONFIG=http://10.1.2.0:8000/testing-meta.json"


exit 0

