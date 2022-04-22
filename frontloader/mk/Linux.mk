
PKG_CONFIG := PKG_CONFIG_PATH='$(PKG_CONFIG_PATH)' PKG_CONFIG_SYSROOT_DIR='$(PKG_CONFIG_SYSROOT_DIR)' pkg-config

CFLAGS_deps := $(shell $(PKG_CONFIG) openssl --cflags)

LDFLAGS += $(shell $(PKG_CONFIG) openssl --libs)

CFLAGS += ${CFLAGS_deps}
CFLAGS += -Wno-format-truncation

LDFLAGS += -rdynamic
