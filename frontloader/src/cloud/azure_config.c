#include "azure.h"

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

#include "config.h"

int
azure_config_reload(const ntv_t *meta_config)
{
  return 0;
}


static ntv_t *
load_metaconfig(void)
{
  const char *url = "http://169.254.169.254/metadata/instance/compute/userData?api-version=2021-01-01&format=text";

  scoped_http_result(hcr);
  trace(LOG_DEBUG, "Loading userdata from %s", url);

  char errbuf[512];
  int r = http_client_request(&hcr, url,
                              HCR_TIMEOUT(2),
                              HCR_HEADER("Metadata", "true"),
                              HCR_ERRBUF(errbuf, sizeof(errbuf)),
                              NULL);
  if(r) {
    trace(LOG_CRIT, "Failed to load Azure userdata: %s", errbuf);
    return NULL;
  }

  trace(LOG_DEBUG, "Loaded userdata from %s", url);

  scoped_char *json = malloc(hcr.hcr_bodysize);
  size_t jsonlen = base64_decode((uint8_t *)json,
                                 (const char *)hcr.hcr_body,
                                 hcr.hcr_bodysize);
  json[jsonlen] = 0;

  ntv_t *conf = ntv_json_deserialize(json, errbuf, sizeof(errbuf));
  if(conf == NULL) {
    trace(LOG_ERR, "Failed to parse JSON from %s -- %s", url, errbuf);
  }
  return conf;
}



struct ntv *
azure_apply_meta_data(void)
{
  scoped_ntv_t *metadata = azure_vm_get_machine_identity();

  const ntv_t *compute = ntv_get_map(metadata, "compute");

  const char *vmId = ntv_get_str(compute, "vmId");
  if(vmId == NULL)
    return NULL;
  setenv("FL_INSTANCE_ID", vmId, 1);

  const char *zone = ntv_get_str(compute, "zone");
  if(zone != NULL) {
    trace(LOG_DEBUG, "Azure availability zone: %s", zone);
    setenv("FL_ZONE", zone, 1);
  }

  const char *hostname = ntv_get_str(compute, "name");
  if(hostname != NULL) {
    if(sethostname(hostname, strlen(hostname)) == -1) {
      trace(LOG_CRIT, "Failed to set hostname to %s : %s",
            hostname, strerror(errno));
    } else {
      trace(LOG_NOTICE, "Hostname set to %s", hostname);
    }
  }

  azure_monitor_init(metadata);

  return load_metaconfig();
}
