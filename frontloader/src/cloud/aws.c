#include "aws.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>

#include "libsvc/aws.h"
#include "libsvc/ntv.h"
#include "libsvc/strvec.h"
#include "libsvc/misc.h"
#include "libsvc/http_client.h"
#include "libsvc/trace.h"

#include "config.h"

int
aws_config_reload_sm(const ntv_t *meta_config)
{
  int r;
  char errbuf[512];

  scoped_strvec(iamroles);

  const char *secret_id = ntv_get_str(meta_config, "secretId");
  const char *region    = ntv_get_str(meta_config, "region");

  const char *iamrole = ntv_get_str(meta_config, "machineRole");
  if(iamrole)
    strvec_push(&iamroles, iamrole);

  const char *key_id = NULL;
  const char *secret = NULL;
  const char *token = NULL;

  scoped_char *listcredsurl =
    fmt("http://169.254.169.254/latest/meta-data/iam/security-credentials");

  scoped_http_result(rolesreq);

  r = http_client_request(&rolesreq, listcredsurl,
                          HCR_TIMEOUT(20),
                          HCR_ERRBUF(errbuf, sizeof(errbuf)),
                          NULL);
  if(r) {
    trace(LOG_INFO,
          "AWS meta-data: Unable to list security-credentials at %s: %s",
          listcredsurl, errbuf);
  } else {
    strvec_split(&iamroles, rolesreq.hcr_body, "\n", 0);
  }

  if(iamroles.count == 0) {
    trace(LOG_ERR, "AWS meta-data: "
          "Machine role not configured and none could be looked up");
    return -1;
  }

  for(size_t i = 0; i < iamroles.count; i++) {
    scoped_http_result(machinereq);
    const char *iamrole = strvec_get(&iamroles, i);

    scoped_char *iamroleurl =
      fmt("http://169.254.169.254/latest/meta-data/iam/security-credentials/%s",
          iamrole);

    r = http_client_request(&machinereq, iamroleurl,
                            HCR_TIMEOUT(20),
                            HCR_FLAGS(HCR_DECODE_BODY_AS_JSON),
                            HCR_ERRBUF(errbuf, sizeof(errbuf)),
                            NULL);
    if(r) {
      trace(LOG_ERR,
            "AWS meta-data: Unable to query %s for machine credentials: %s",
            iamroleurl, errbuf);
      continue;
    }

    key_id = ntv_get_str(machinereq.hcr_json_result, "AccessKeyId");
    secret = ntv_get_str(machinereq.hcr_json_result, "SecretAccessKey");
    token  = ntv_get_str(machinereq.hcr_json_result, "Token");

    scoped_ntv_t *req = ntv_map("SecretId", ntv_str(secret_id), NULL);
    scoped_char *body = ntv_json_serialize_to_str(req, 0);
    scoped_char *bodyhash = aws_SHA256_hex(body, strlen(body));

    scoped_char *host = fmt("secretsmanager.%s.amazonaws.com", region);

    time_t now = time(NULL);
    scoped_char *isodate = aws_isodate(now);

    scoped_ntv_t *headers =
      ntv_map("host", ntv_str(host),
              "x-amz-target", ntv_str("secretsmanager.GetSecretValue"),
              "x-amz-date", ntv_str(isodate),
              "x-amz-security-token", ntv_str(token),
              NULL);

    aws_creds_t creds = {
      .id = key_id,
      .secret = secret
    };

    scoped_char *auth_header =
      aws_sig4_gen_auth_header("POST",
                               "/",
                               NULL,
                               headers,
                               bodyhash,
                               now,
                               creds,
                               "secretsmanager",
                               region);

    scoped_char *url = fmt("https://%s", host);
    scoped_http_result(hcr);

    r = http_client_request(&hcr, url,
                            HCR_TIMEOUT(20),
                            HCR_FLAGS(HCR_DECODE_BODY_AS_JSON | HCR_NO_FAIL_ON_ERROR),
                            HCR_ERRBUF(errbuf, sizeof(errbuf)),
                            HCR_HEADER("x-amz-target",
                                       "secretsmanager.GetSecretValue"),
                            HCR_HEADER("x-amz-date", isodate),
                            HCR_HEADER("x-amz-security-token", token),
                            HCR_HEADER("x-amz-content-sha256", bodyhash),
                            HCR_HEADER("authorization", auth_header),
                            HCR_POSTDATA(body, strlen(body),
                                         "application/x-amz-json-1.1"),
                            NULL);
    if(r) {
      trace(LOG_ERR, "Unable to query AWS SM configuration: %s",
            errbuf);
      continue;
    }
    if(hcr.hcr_http_status != 200) {
      trace(LOG_ERR, "Unable to query AWS SM configuration: %s",
            hcr.hcr_body);
      continue;
    }

    const char *configstr = ntv_get_str(hcr.hcr_json_result, "SecretString");
    config_apply_json(configstr, ntv_get_str(hcr.hcr_json_result, "Name"));

    return 0;
  }
  return -1;
}


static char *
get_str_from_url(const char *url)
{
  scoped_http_result(hcr);

  char errbuf[512];
  int r = http_client_request(&hcr, url,
                              HCR_TIMEOUT(20),
                              HCR_ERRBUF(errbuf, sizeof(errbuf)),
                              NULL);
  if(r) {
    trace(LOG_CRIT, "Failed to query: %s", url);
    return NULL;
  }

  // Steal data (always NUL terminated)
  char *ret = hcr.hcr_body;
  hcr.hcr_body = NULL;
  return ret;
}



#define EC2_METADATA "http://169.254.169.254/latest/meta-data/"


static ntv_t *
load_metaconfig(const char *url)
{
  scoped_http_result(hcr);

  trace(LOG_DEBUG, "Loading metaconfig from %s", url);

  char errbuf[512];
  int r = http_client_request(&hcr, url,
                              HCR_TIMEOUT(20),
                              HCR_FLAGS(HCR_DECODE_BODY_AS_JSON),
                              HCR_ERRBUF(errbuf, sizeof(errbuf)),
                              NULL);
  if(r) {
    trace(LOG_CRIT, "Failed to load EC2 userdata: %s", errbuf);
    return NULL;
  }

  trace(LOG_DEBUG, "Loaded metaconfig from %s", url);
  ntv_t *meta_config = hcr.hcr_json_result;
  hcr.hcr_json_result = NULL;
  return meta_config;
}




ntv_t *
ec2_apply_meta_data(void)
{
  scoped_char *instance_id =
    get_str_from_url(EC2_METADATA"instance-id");

  if(instance_id == NULL)
    return NULL;
  setenv("FL_INSTANCE_ID", instance_id, 1);

  scoped_char *zone =
    get_str_from_url(EC2_METADATA"placement/availability-zone");
  setenv("FL_ZONE", zone, 1);
  if(zone != NULL) {
    trace(LOG_DEBUG, "EC2 availability zone: %s", zone);
  }
  scoped_char *hostname =
    zone ? fmt("%s.%s", instance_id, zone) : strdup(instance_id);

  if(sethostname(hostname, strlen(hostname)) == -1) {
    trace(LOG_CRIT, "Failed to set hostname to %s : %s",
          hostname, strerror(errno));
  } else {
    trace(LOG_NOTICE, "Hostname set to %s", hostname);
  }

  scoped_char *macaddr =
    get_str_from_url(EC2_METADATA"network/interfaces/macs/");
  if(macaddr != NULL) {

    macaddr[strspn(macaddr, "0123456789abcdefABCDEF:")] = 0;
    trace(LOG_DEBUG, "EC2 macaddr: %s", macaddr);

    scoped_char *ipv4_url =
      fmt(EC2_METADATA"network/interfaces/macs/%s/public-ipv4s", macaddr);
    scoped_char *ipv4 = get_str_from_url(ipv4_url);
    if(ipv4 != NULL) {
      ipv4[strspn(ipv4, ".0123456789")] = 0;
      trace(LOG_DEBUG, "EC2 ipv4: %s", ipv4);
      setenv("FL_IPV4", ipv4, 1);
    }

    scoped_char *ipv6_url =
      fmt(EC2_METADATA"network/interfaces/macs/%s/ipv6s", macaddr);
    scoped_char *ipv6 = get_str_from_url(ipv6_url);
    if(ipv6 != NULL) {
      ipv6[strspn(ipv6, "0123456789abcdefABCDEF:")] = 0;
      trace(LOG_DEBUG, "EC2 ipv4: %s", ipv6);
      setenv("FL_IPV6", ipv6, 1);
    }
  }

  return load_metaconfig("http://169.254.169.254/latest/user-data");
}


