#define _GNU_SOURCE 1
#include <pthread.h>
#include <errno.h>
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <dlfcn.h>
#include <sys/resource.h>

#include "libsvc/misc.h"
#include "libsvc/strtab.h"
#include "libsvc/strvec.h"
#include "libsvc/ntv.h"
#include "libsvc/init.h"
#include "libsvc/trace.h"
#include "libsvc/http_client.h"
#include "libsvc/cfg.h"
#include "libsvc/task.h"
#include "libsvc/http.h"
#include "libsvc/vec.h"

#include "stats.h"
#include "config.h"

static pthread_mutex_t datadog_config_mutex = PTHREAD_MUTEX_INITIALIZER;
static char *datadog_api_key;
static ntv_t *datadog_tags;

static void
datadog_accumulate(const ntv_t *values, ntv_t *output, int now,
                   float scaler)
{
  NTV_FOREACH(v, values) {
    ntv_t *o = ntv_get_mutable_list(output, v->ntv_name);
    switch(v->ntv_type) {
    default:
      break;
    case NTV_INT:
      if(scaler == 1.0) {
        ntv_set(o, NULL, ntv_list(ntv_int(now), ntv_int(v->ntv_s64), NULL));
      } else {
        ntv_set(o, NULL, ntv_list(ntv_int(now),
                                  ntv_double(v->ntv_s64 * scaler), NULL));
      }
      break;

    case NTV_DOUBLE:
      ntv_set(o, NULL, ntv_list(ntv_int(now),
                                ntv_double(v->ntv_double * scaler), NULL));
      break;
    }
  }
}



static void
datadog_post(void *aux)
{
  scoped_ntv_t *msg = aux;
  char errbuf[512];
  scoped_http_result(hcr);

  if(http_client_request(&hcr, ntv_get_str(msg, "url"),
                         HCR_ERRBUF(errbuf, sizeof(errbuf)),
                         HCR_TIMEOUT(15),
                         HCR_POSTJSON(ntv_get_map(msg, "body")),
                         NULL)) {
    trace(LOG_NOTICE, "Unable to send globalStats to datadog -- %s", errbuf);
  }
}


static void
datadog_send(ntv_t *accumulator, int interval)
{
  char hostname[256];
  if(gethostname(hostname, sizeof(hostname)))
    return;

  pthread_mutex_lock(&datadog_config_mutex);
  if(datadog_api_key == NULL) {
    pthread_mutex_unlock(&datadog_config_mutex);
    return;
  }

  ntv_t *rates  = ntv_get_mutable_map(accumulator, "rates");
  ntv_t *gauges = ntv_get_mutable_map(accumulator, "gauges");

  const char *zone = getenv("FL_ZONE");
  scoped_char *zone_tag = zone ? fmt("zone:%s", zone) : NULL;

  scoped_ntv_t *tags =
    datadog_tags ? ntv_copy(datadog_tags) : ntv_create_list();

  ntv_set(tags, NULL, zone_tag);

  ntv_t *series = ntv_create_list();
  ntv_t *f;
  while((f = ntv_detach_field(rates, NTV_INDEX(0))) != NULL) {
    ntv_t *s = ntv_create_map();
    ntv_set(s, "metric", f->ntv_name);
    ntv_set(s, "host", hostname);
    ntv_set(s, "interval", interval);
    ntv_set(s, "type", "rate");
    ntv_set(s, "points", f);
    ntv_set(s, "tags", ntv_copy(tags));
    ntv_set(series, NULL, s);
  }

  while((f = ntv_detach_field(gauges, NTV_INDEX(0))) != NULL) {
    ntv_t *s = ntv_create_map();
    ntv_set(s, "metric", f->ntv_name);
    ntv_set(s, "host", hostname);
    ntv_set(s, "points", f);
    ntv_set(s, "tags", ntv_copy(tags));
    ntv_set(series, NULL, s);
  }

  ntv_t *body = ntv_map("series", series, NULL);

  scoped_char *url =
    fmt("https://app.datadoghq.com/api/v1/series?api_key=%s", datadog_api_key);

  pthread_mutex_unlock(&datadog_config_mutex);
  task_run(datadog_post, ntv_map("url", ntv_str(url),
                                 "body", body,
                                 NULL));
}

static void
datadog_emit(const ntv_t *gauges, const ntv_t *rates, int interval)
{
  static ntv_t *accumulator;
  static int accumulator_cnt;

  if(accumulator == NULL)
    accumulator = ntv_create_map();

  time_t now = time(NULL);
  datadog_accumulate(rates,  ntv_get_mutable_map(accumulator, "rates"),
                     now, 1.0f / interval);
  datadog_accumulate(gauges, ntv_get_mutable_map(accumulator, "gauges"), now,
                     1.0f);

  accumulator_cnt++;
  if(accumulator_cnt == 3) {
    datadog_send(accumulator, interval);
    ntv_release(accumulator);
    accumulator = NULL;

    accumulator_cnt = 0;
  }

}



static VEC_HEAD(, stats_global_cb_t *) global_stat_fns;

void
stats_global_register(stats_global_cb_t *fn)
{
  VEC_PUSH_BACK(&global_stat_fns, fn);
}


/**
 *
 */
static void *
stats_collect_thread(void *aux)
{
  int interval = 10;

  int64_t nextwakeup = get_ts_mono() + interval * 1000 * 1000;

  while(1) {

    int64_t sleeptime = nextwakeup - get_ts_mono();

    usleep(sleeptime + 1000);

    nextwakeup += interval * 1000 * 1000;

    scoped_ntv_t *gauges = ntv_create_map();
    scoped_ntv_t *rates = ntv_create_map();

    for(int i = 0; i < VEC_LEN(&global_stat_fns); i++) {
      stats_global_cb_t *fn = VEC_ITEM(&global_stat_fns, i);
      fn(gauges, rates);
    }
    datadog_emit(gauges, rates, interval);
  }
  return NULL;
}



/**
 *
 */
static void
stats_init(void)
{
  pthread_attr_t attr;
  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
  pthread_t tid;
  pthread_create(&tid, &attr, stats_collect_thread, NULL);
  pthread_attr_destroy(&attr);
}

INITME(stats_init, NULL, 2);



static int
datadog_reconfigure(const ntv_t *config)
{
  const ntv_t *dd = ntv_get_map(config, "datadog");

  pthread_mutex_lock(&datadog_config_mutex);
  strset(&datadog_api_key, ntv_get_str(dd, "api_key"));
  ntv_release(datadog_tags);
  datadog_tags = ntv_copy(ntv_get_list(dd, "tags"));
  pthread_mutex_unlock(&datadog_config_mutex);
  return 0;
}


CONFIG_SUB(datadog_reconfigure, "datadog", 3000);

static void
stats_meminfo(struct ntv *gauges, struct ntv *rates)
{
  FILE *meminfo = fopen("/proc/meminfo", "re");
  if(meminfo != NULL) {
    char kind[64] = {};
    int64_t value;
    while(fscanf(meminfo, "%63s %"SCNd64" kB\n", kind, &value) == 2) {
      if(!strcmp(kind, "MemAvailable:"))
        ntv_set(gauges, "system.mem.usable", value / 1024);
      if(!strcmp(kind, "MemFree:"))
        ntv_set(gauges, "system.mem.free", value / 1024);
      if(!strcmp(kind, "MemTotal:"))
        ntv_set(gauges, "system.mem.total", value / 1024);
      if(!strcmp(kind, "Slab:"))
        ntv_set(gauges, "system.mem.slab", value / 1024);
      if(!strcmp(kind, "Mlocked:"))
        ntv_set(gauges, "system.mem.locked", value / 1024);
      if(!strcmp(kind, "Cached:"))
        ntv_set(gauges, "system.mem.cached", value / 1024);
    }
    fclose(meminfo);
  }
}

static void
stats_cpu(struct ntv *gauges, struct ntv *rates)
{
  FILE *stat = fopen("/proc/stat", "re");
  if(stat != NULL) {
    char kind[64] = {};

#define NUM_STATS 10
    int64_t stats[NUM_STATS];
    static int64_t p_stats[NUM_STATS];
    static int p_set;

    static const char *stat_names[NUM_STATS] = {
      "user",
      "nice",
      "system",
      "idle",
      "iowait",
      "irq",
      "softirq",
      "steal",
      "guest",
      "guest_nice",
    };

    while(fscanf(stat, "%63s %"SCNd64" %"SCNd64" %"SCNd64" %"SCNd64" %"
                 SCNd64" %"SCNd64" %"SCNd64" %"SCNd64" %"SCNd64" %"SCNd64, kind,
                 &stats[0], &stats[1], &stats[2], &stats[3], &stats[4],
                 &stats[5], &stats[6], &stats[7], &stats[8], &stats[9]) ==
          NUM_STATS + 1) {

      if(!strcmp(kind, "cpu")) {
        if(p_set) {
          uint64_t delta[NUM_STATS];
          uint64_t delta_sum = 0;
          for(int i = 0; i < NUM_STATS; i++) {
            delta[i] = stats[i] - p_stats[i];
            delta_sum += delta[i];
          }

          for(int i = 0; i < NUM_STATS; i++) {
            float v = 100.0 * delta[i] / delta_sum;
            scoped_char *name = fmt("system.cpu.%s", stat_names[i]);
            ntv_set(gauges, name, v);
          }
        }

        for(int i = 0; i < NUM_STATS; i++) {
          p_stats[i] = stats[i];
        }
        p_set = 1;
      }
    }
    fclose(stat);
  }
}


static void
stats_net(struct ntv *gauges, struct ntv *rates)
{
  FILE *fp = fopen("/proc/net/snmp", "r");
  if(fp == NULL)
    return;

  long InDatagrams;
  long NoPorts;
  long InErrors;
  long OutDatagrams;
  long RcvbufErrors;
  long SndbufErrors;
  long InCsumErrors;
  long IgnoredMulti;

  static long last_InDatagrams;
  static long last_NoPorts;
  static long last_InErrors;
  static long last_OutDatagrams;
  static long last_RcvbufErrors;
  static long last_SndbufErrors;
  static long last_InCsumErrors;
  //  static long last_IgnoredMulti;

  while(!feof(fp)) {
    char buf[512];
    if(fgets(buf, sizeof(buf) - 1, fp) == NULL)
      break;

    int r = sscanf(buf, "Udp: %ld %ld %ld %ld %ld %ld %ld %ld\n",
                   &InDatagrams, &NoPorts, &InErrors, &OutDatagrams,
                   &RcvbufErrors, &SndbufErrors, &InCsumErrors, &IgnoredMulti);
    if(r == 8) {

      ntv_set(rates, "system.net.udp.in_datagrams",   (double)(InDatagrams  - last_InDatagrams));
      ntv_set(rates, "system.net.udp.no_ports",       (double)(NoPorts      - last_NoPorts));
      ntv_set(rates, "system.net.udp.in_errors",      (double)(InErrors     - last_InErrors));
      ntv_set(rates, "system.net.udp.in_csum_errors", (double)(InCsumErrors - last_InCsumErrors));
      ntv_set(rates, "system.net.udp.out_datagrams",  (double)(OutDatagrams - last_OutDatagrams));
      ntv_set(rates, "system.net.udp.rcv_buf_errors", (double)(RcvbufErrors - last_RcvbufErrors));
      ntv_set(rates, "system.net.udp.snd_buf_errors", (double)(SndbufErrors - last_SndbufErrors));

      last_InDatagrams = InDatagrams;
      last_NoPorts = NoPorts;
      last_InErrors = InErrors;
      last_OutDatagrams = OutDatagrams;
      last_RcvbufErrors = RcvbufErrors;
      last_SndbufErrors = SndbufErrors;
      last_InCsumErrors = InCsumErrors;

    }
  }
  fclose(fp);
}



GSTATS(stats_meminfo);
GSTATS(stats_cpu);
GSTATS(stats_net);
