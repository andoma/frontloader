set -e

HOSTDIR=`cd $1/../host && pwd`
echo Hostdir: ${HOSTDIR}

make -C ../frontloader BUILD=buildroot HOSTDIR="${HOSTDIR}" -j
make -C ../frontloader BUILD=buildroot HOSTDIR="${HOSTDIR}" DESTDIR=$1 prefix=/usr install
rm -f $1/usr/bin/coreuploader
ln $1/usr/bin/frontloader $1/usr/bin/coreuploader
