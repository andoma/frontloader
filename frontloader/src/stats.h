#pragma once

#include "libsvc/init.h"

struct ntv;

typedef void (stats_global_cb_t)(struct ntv *gauges, struct ntv *rates);

void stats_global_register(stats_global_cb_t *);

#define GSTATS(fn_)                                                     \
  static void LIBSVC_JOIN(fn_, __LINE__)(void) __attribute__((constructor)); \
  static void LIBSVC_JOIN(fn_, __LINE__)(void) { stats_global_register(fn_); }
