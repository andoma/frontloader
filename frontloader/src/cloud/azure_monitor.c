#include "azure.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>

#include "libsvc/ntv.h"
#include "libsvc/strvec.h"
#include "libsvc/misc.h"
#include "libsvc/http_client.h"
#include "libsvc/trace.h"
#include "libsvc/azure.h"

#include "logging.h"

typedef struct {
  const char *hostname;
  const char *vmid;
  const char *region;
  const char *resource_id;
} vm_instance_metadata_t;


static ntv_t *
get_monitor_config(const char *auth_header)
{
  scoped_ntv_t *metadata = azure_vm_get_machine_identity();
  const ntv_t *compute = ntv_get_map(metadata, "compute");
  if(compute == NULL) {
    trace(LOG_ERR, "VM metadata contains to 'compute' map");
    return NULL;
  }

  scoped_char *cfgurl =
    fmt("https://global.handler.control.monitor.azure.com/locations/%s/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Compute/virtualMachines/%s/agentConfigurations?platform=linux&includeMeConfig=true&api-version=2022-06-02",
        ntv_get_str(compute, "location"),
        ntv_get_str(compute, "subscriptionId"),
        ntv_get_str(compute, "resourceGroupName"),
        ntv_get_str(compute, "name"));

  scoped_http_result(hcr);

  char errbuf[512];

  if(http_client_request(&hcr, cfgurl,
                         HCR_TIMEOUT(20),
                         HCR_FLAGS(HCR_DECODE_BODY_AS_JSON),
                         HCR_ERRBUF(errbuf, sizeof(errbuf)),
                         HCR_HEADER("Authorization", auth_header),
                         NULL)) {
    trace(LOG_ERR, "Unable to get monitor config from %s -- %s",
          cfgurl, errbuf);
    return NULL;
  }

  ntv_t *r = hcr.hcr_json_result;
  hcr.hcr_json_result = NULL;
  return r;
}

static const char *severity_to_str[8] = {
  "emerg", "alert", "crit", "error", "warning", "notice", "info", "debug"
};


static ntv_t *
logline_to_ods_item(const logline_t *l, const vm_instance_metadata_t *vim)
{
  struct tm tm;
  localtime_r(&l->tv.tv_sec, &tm); // We are always in UTC

  char rfc3339_date[64];
  snprintf(rfc3339_date, sizeof(rfc3339_date),
           "%04d-%02d-%02dT%02d:%02d:%02d.%06dZ",
           tm.tm_year + 1900,
           tm.tm_mon + 1,
           tm.tm_mday,
           tm.tm_hour,
           tm.tm_min,
           tm.tm_sec,
           (int)l->tv.tv_usec);

  return ntv_map("Facility", ntv_str(logline_faclility_str(l)),
                 "SeverityNumber", ntv_strf("%d", l->pri & 7),
                 "Timestamp", ntv_strf("%04d-%02d-%02dT%02d:%02d:%02d.%06dZ",
                                       tm.tm_year + 1900,
                                       tm.tm_mon + 1,
                                       tm.tm_mday,
                                       tm.tm_hour,
                                       tm.tm_min,
                                       tm.tm_sec,
                                       (int)l->tv.tv_usec),
                 "Message", ntv_str(l->msg),
                 "ProcessId", ntv_strf("%u", l->pid),
                 "Severity", ntv_str(severity_to_str[l->pri & 7]),
                 "Host", ntv_str(vim->hostname),
                 "ident", ntv_str(l->procname),
                 NULL);
}


typedef struct {
  logsink_t *o_logsink;
  const vm_instance_metadata_t *o_metadata;
  char *o_access_token;
} ods_t;


static void
rfc3999now(char *buf, size_t len)
{
  struct timeval tv;
  gettimeofday(&tv, NULL);

  struct tm tm;
  localtime_r(&tv.tv_sec, &tm); // We are always in UTC

  snprintf(buf, len,
           "%04d-%02d-%02dT%02d:%02d:%02d.%06dZ",
           tm.tm_year + 1900,
           tm.tm_mon + 1,
           tm.tm_mday,
           tm.tm_hour,
           tm.tm_min,
           tm.tm_sec,
           (int)tv.tv_usec);
}


static char *
ods_get_auth_header(const ntv_t *conf)
{
  const char *url = ntv_get_str(conf, "tokenEndpointUri");
  if(url == NULL) {
    trace(LOG_ERR, "Channel config contains to tokenEndpointUri");
    return NULL;
  }

  scoped_ntv_t *token = azure_vm_get_machine_token("https://monitor.azure.com/");
  if(token == NULL) {
    return NULL; // Callee logs
  }

  scoped_char *auth_header = fmt("%s %s",
                                 ntv_get_str(token, "token_type"),
                                 ntv_get_str(token, "access_token"));

  scoped_http_result(hcr);
  char errbuf[512];
  if(http_client_request(&hcr, url,
                         HCR_TIMEOUT(5),
                         HCR_FLAGS(HCR_DECODE_BODY_AS_JSON),
                         HCR_ERRBUF(errbuf, sizeof(errbuf)),
                         HCR_HEADER("Authorization", auth_header),
                         NULL)) {
    trace(LOG_ERR, "Unable to get endpoint token from %s -- %s",
          url, errbuf);
    return NULL;
  }


  return fmt("Bearer %s", ntv_get_str(hcr.hcr_json_result, "ingestionAuthToken"));
}




static void
ods_syslog_transmit(ods_t *o, ntv_t *items)
{
  logsink_t *ls = o->o_logsink;
  const ntv_t *conf = ls->ls_conf;

  scoped_ntv_t *doc =
    ntv_map("DataType", ntv_str("LINUX_SYSLOGS_BLOB"),
            "IPName" , ntv_str("LogManagement"),
            "ManagementGroupId", ntv_str("00000000-0000-0000-0000-000000000002"),
            "sourceHealthServiceId", ntv_str(o->o_metadata->vmid),
            "type", ntv_str("JsonData"),
            "DataItems", items,
            NULL);

  scoped_http_result(hcr);
  char errbuf[512];

  scoped_char *url = fmt("%s/OperationalData.svc/PostJsonDataItems?api-version=2016-04-01",
                         ntv_get_str(conf, "endpoint"));

  for(int i = 0; i < 10; i++) {
    if(o->o_access_token == NULL) {
      o->o_access_token = ods_get_auth_header(conf);
    }

    char date[100];
    rfc3999now(date, sizeof(date));

    if(!http_client_request(&hcr, url,
                            HCR_TIMEOUT(5),
                            HCR_FLAGS(HCR_VERBOSE),
                            HCR_POSTJSON(doc),
                            HCR_ERRBUF(errbuf, sizeof(errbuf)),
                            HCR_HEADER("Authorization", o->o_access_token),
                            HCR_HEADER("x-ms-AzureRegion", o->o_metadata->region),
                            HCR_HEADER("x-ms-AzureResourceId", o->o_metadata->resource_id),
                            HCR_HEADER("x-ms-Date", date),
                            HCR_HEADER("x-ms-UUID", o->o_metadata->vmid),
                            //                         HCR_HEADER("x-ms-OMSCloudId", dmidthing),
                            NULL)) {
      break;
    }

    trace(LOG_ERR, "Unable to POST %s -- %s", url, errbuf);
    sleep(2 * i + 1);
    free(o->o_access_token);
    o->o_access_token = NULL;
  }
}


static void *
ods_syslog_thread(void *arg)
{
  ods_t *ods = arg;
  logsink_t *ls = ods->o_logsink;

  int max_lines_per_request = 50;
  int transmit_threshold = 20; // If we have more than this # of lines, always transmit
  int transmit_interval = 10; // otherwise wait for at most this many seconds
  int64_t next_xmit = get_ts_mono() + transmit_interval * 1000000;

  scoped_ntv_t *instance_metadata = NULL;

  pthread_mutex_lock(&log_mutex);

  while(ls->ls_running) {

    if(ls->ls_num_loglines < transmit_threshold) {

      if(ls->ls_num_loglines == 0) {
        pthread_cond_wait(&ls->ls_cond, &log_mutex);
        continue;
      }

      struct timespec ts = {
        .tv_sec = next_xmit / 1000000LL,
        .tv_nsec = (next_xmit % 1000000LL) * 1000
      };
      if(pthread_cond_timedwait(&ls->ls_cond, &log_mutex, &ts) != ETIMEDOUT) {
        continue;
      }
    }

    ntv_t *items = ntv_create_list();
    for(int i = 0; i < max_lines_per_request; i++) {
      logline_t *l = TAILQ_FIRST(&ls->ls_lines);
      if(l == NULL)
        break;
      ntv_add_ntv(items, NULL, logline_to_ods_item(l, ods->o_metadata));
      ls->ls_num_loglines--;
      TAILQ_REMOVE(&ls->ls_lines, l, link);
      logline_destroy(l);
    }

    pthread_mutex_unlock(&log_mutex);

    // Takes ownership of 'items'
    ods_syslog_transmit(ods, items);

    // Set new deadline for next transmission
    next_xmit = get_ts_mono() + transmit_interval * 1000000;
    pthread_mutex_lock(&log_mutex);
  }
  pthread_mutex_unlock(&log_mutex);
  free(ods->o_access_token);
  free(ods);
  return NULL;
}


static const ntv_t *
find_channel(const ntv_t *channels, const char *search)
{
  NTV_FOREACH_TYPE(channel, channels, NTV_MAP) {
    const char *id = ntv_get_str(channel, "id");
    if(id != NULL && !strcmp(id, search))
      return channel;
  }
  return NULL;
}


static void
add_datasource_syslog(const ntv_t *datasource, const ntv_t *channels,
                      const vm_instance_metadata_t *vim,
                      struct logsink_list *sinks)
{
  //  const ntv_t *configuration = ntv_get_map(datasource, "configuration");
  const ntv_t *sendToChannels = ntv_get_list(datasource, "sendToChannels");
  NTV_FOREACH_TYPE(sendToChannel, sendToChannels, NTV_STRING) {
    const ntv_t *channel = find_channel(channels, sendToChannel->ntv_string);

    const char *protocol = ntv_get_str(channel, "protocol");
    if(protocol == NULL)
      continue;

    if(!strcmp(protocol, "ods")) {

      logsink_t *ls = logsink_find(channel, sinks);
      if(ls != NULL) {
        ls->ls_mark = 0;
      } else {
        // Create it
        ls = logsink_create(channel, sinks);

        ods_t *ods = calloc(1, sizeof(ods_t));
        ods->o_logsink = ls;
        ods->o_metadata = vim;
        pthread_create(&ls->ls_tid, NULL, ods_syslog_thread, ods);
      }
    }
  }
}


static void
add_datasource_perfCounter(const ntv_t *datasource,
                           const ntv_t *channels,
                           const vm_instance_metadata_t *vim)
{
  const ntv_t *sendToChannels = ntv_get_list(datasource, "sendToChannels");
  NTV_FOREACH_TYPE(sendToChannel, sendToChannels, NTV_STRING) {
    //    const ntv_t *channel = find_channel(channels, sendToChannel->ntv_string);
  }
}


static int
update_monitor_config(const vm_instance_metadata_t *vim,
                      struct logsink_list *logsinks)
{
  scoped_ntv_t *token = azure_vm_get_machine_token("https://monitor.azure.com/");
  if(token == NULL)
    return -1;

  scoped_char *auth_header = fmt("%s %s",
                                 ntv_get_str(token, "token_type"),
                                 ntv_get_str(token, "access_token"));

  scoped_ntv_t *doc = get_monitor_config(auth_header);
  if(doc == NULL)
    return -1;

  logsinks_lock_mark(logsinks);

  const ntv_t *confs = ntv_get_list(doc, "configurations");
  NTV_FOREACH_TYPE(conf, confs, NTV_MAP) {

    const ntv_t *content = ntv_get_map(conf, "content");
    const ntv_t *channels = ntv_get_list(content, "channels");
    const ntv_t *datasources = ntv_get_list(content, "dataSources");

    NTV_FOREACH_TYPE(datasource, datasources, NTV_MAP) {
      const char *kind = ntv_get_str(datasource, "kind");
      if(kind == NULL)
        continue;

      if(!strcmp(kind, "syslog")) {
        add_datasource_syslog(datasource, channels, vim, logsinks);
      } else if(!strcmp(kind, "perfCounter")) {
        add_datasource_perfCounter(datasource, channels, vim);
      }
    }
  }

  // Will also unlock mutex
  logsinks_sweep_unlock_reap(logsinks);

  pthread_mutex_unlock(&log_mutex);
  return 0;
}


__attribute__((noreturn))
static void *
azure_monitor_mgmt_thread(void *aux)
{
  ntv_t *instance_metadata = aux;
  static struct logsink_list logsinks;

  const ntv_t *compute = ntv_get_map(instance_metadata, "compute");

  vm_instance_metadata_t vim = {};

  vim.hostname = ntv_get_str(compute, "name");
  vim.vmid = ntv_get_str(compute, "vmId");
  vim.region = ntv_get_str(compute, "location");
  vim.resource_id = fmt("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Compute/virtualMachines/%s",
                        ntv_get_str(compute, "subscriptionId"),
                        ntv_get_str(compute, "resourceGroupName"),
                        vim.hostname);

  LIST_INIT(&logsinks);

  while(1) {
    update_monitor_config(&vim, &logsinks);
    sleep(60);
  }
}


void
azure_monitor_init(const ntv_t *instance_metadata)
{
  pthread_attr_t attr;
  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
  pthread_t tid;
  pthread_create(&tid, &attr, azure_monitor_mgmt_thread, ntv_copy(instance_metadata));
  pthread_attr_destroy(&attr);
}
