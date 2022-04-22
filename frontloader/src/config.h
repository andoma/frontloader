#pragma once

#include "libsvc/init.h"

struct ntv;
typedef int (config_update_cb_t)(const struct ntv *cfg);

typedef struct config_registration {
  config_update_cb_t *cb;
  const char *name;
  int prio;
} config_registration_t;

void config_register_update(config_registration_t cr);

void config_init(const char *source);

void config_inhibit_updates(void);

int config_reload(void);

void config_start_autoreloader(void);

#define CONFIG_SUB(fn_, name_, prio_)                                  \
  static void LIBSVC_JOIN(fn_, __LINE__)(void) __attribute__((constructor)); \
  static void LIBSVC_JOIN(fn_, __LINE__)(void) {                        \
    config_registration_t cr = {fn_, name_, prio_};                  \
    config_register_update(cr); }
