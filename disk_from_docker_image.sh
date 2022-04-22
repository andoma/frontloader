#!/bin/bash

set -x
set -e

make -C bootloader

(cat bootloader/bootloader &&
     docker image save $1|tar -x -O -f - --wildcards "*/layer.tar"|tar -x -O -f - bzImage) >disk.img
