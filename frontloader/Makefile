PROGNAME := frontloader

WITH_CTRL_SOCK   := yes
WITH_ASYNCIO     := yes
WITH_OPENSSL     := yes
WITH_WS_CLIENT   := yes

CC=gcc

BUILD ?= $(shell uname)

-include mk/${BUILD}.mk

CSTANDARD  := gnu11
CFLAGS_opt := -O2
CFLAGS += -iquotesrc

BUILDDIR = ${CURDIR}/build.${BUILD}

PROG=${BUILDDIR}/${PROGNAME}

SRCS =  src/main.c \
	src/config.c \
	src/runner.c \
	src/fileutil.c \
	src/docker_image.c \
	src/logging.c \
	src/volumes.c \
	src/coreupload.c \
	src/powerbtn.c \
	src/stats.c \
	src/sysupgrade.c \
	src/control.c \
	src/sysparams.c \

SRCS += \
	src/cloud/aws.c \
	src/cloud/azure_config.c \
	src/cloud/azure_monitor.c \


CFLAGS += -DCONFIGKEY=\"${CONFIGKEY}\"

CFLAGS_deps += $(shell $(PKG_CONFIG) --cflags libarchive)
LDFLAGS     += $(shell $(PKG_CONFIG) --libs   libarchive)

LDFLAGS += -lz

install: ${PROG}
	install -D ${PROG} "${DESTDIR}${prefix}/bin/${PROGNAME}"

uninstall:
	rm -f "${prefix}/bin/${PROGNAME}" "${prefix}/bin/${PROGNAME}"

include libsvc/libsvc.mk
-include config.local
-include $(DEPS)

