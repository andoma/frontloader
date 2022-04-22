#include <pthread.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

#include <openssl/evp.h>
#include <openssl/sha.h>

#include <zlib.h>

#include "config.h"

#include "libsvc/atomic.h"
#include "libsvc/vec.h"
#include "libsvc/ntv.h"
#include "libsvc/trace.h"
#include "libsvc/misc.h"
#include "libsvc/http_client.h"
#include "libsvc/aws.h"
#include "libsvc/strvec.h"

static ntv_t *meta_config;

static pthread_mutex_t config_update_mutex = PTHREAD_MUTEX_INITIALIZER;
static ntv_t *config_current;

static int config_no_more_updates;

extern atomic_t g_have_control_connection;

static VEC_HEAD(, config_registration_t) config_update_fns;

void
config_register_update(config_registration_t cr)
{
  VEC_PUSH_BACK(&config_update_fns, cr);
}


static int
config_apply(const char *json, const char *source)
{
  char errbuf[512];
  ntv_t *cfg = ntv_json_deserialize(json, errbuf, sizeof(errbuf));

  pthread_mutex_lock(&config_update_mutex);
  if(config_no_more_updates) {
    pthread_mutex_unlock(&config_update_mutex);
    return 0;
  }

  if(cfg == NULL) {
    trace(LOG_CRIT, "Unable to parse config from %s -- %s", source, errbuf);
  } else {

    if(ntv_cmp(cfg, config_current)) {

      trace(LOG_NOTICE, "Applying new config from %s", source);
      alarm(600);
      for(int i = 0; i < VEC_LEN(&config_update_fns); i++) {
        config_update_cb_t *fn = VEC_ITEM(&config_update_fns, i).cb;
        int r = fn(cfg);
        if(r)
          break;
      }
      alarm(0);
      trace(LOG_NOTICE, "Applied new config from %s", source);
      ntv_release(config_current);
      config_current = cfg;
    } else {
      ntv_release(cfg);
    }
  }

  pthread_mutex_unlock(&config_update_mutex);
  return 0;
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









static int
config_reload_aws_sm(void)
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
    config_apply(configstr, ntv_get_str(hcr.hcr_json_result, "Name"));

    return 0;
  }
  return -1;
}



int
config_reload(void)
{
  char errbuf[512];

  if(meta_config == NULL) {
    trace(LOG_ERR, "No meta config set, nothing will happen");
    return -1;
  }

  const char *type = ntv_get_str(meta_config, "configSource") ?: "plain";
  if(!strcmp(type, "aws-sm")) {
    return config_reload_aws_sm();
  }

  if(strcmp(type, "plain")) {
    trace(LOG_ERR, "Type '%s' meta config is unknown, nothing will happen",
          type);
    return -1;
  }

  const char *config_url = ntv_get_str(meta_config, "url");

  if(config_url == NULL) {
    trace(LOG_ERR, "No 'url' key in meta config, nothing will happen");
    return -1;
  }

  if(mystrbegins(config_url, "http://") ||
     mystrbegins(config_url, "https://")) {
    scoped_http_result(hcr);
    int r = http_client_request(&hcr, config_url,
                                HCR_TIMEOUT(20),
                                HCR_ERRBUF(errbuf, sizeof(errbuf)),
                                NULL);
    if(r) {
      trace(LOG_CRIT, "Unable to load config from %s -- %s", config_url, errbuf);
      return -1;
    }

    return config_apply(hcr.hcr_body, config_url);
  }

  int fd = open(config_url, O_RDONLY);
  if(fd == -1) {
    trace(LOG_CRIT, "Unable to open config from %s -- %s", config_url,
          strerror(errno));
    return -1;
  }

  struct stat st;
  if(fstat(fd, &st)) {
    trace(LOG_CRIT, "Unable to stat config from %s -- %s", config_url,
          strerror(errno));
    close(fd);
    return -1;
  }

  scoped_char *body = malloc(st.st_size + 1);
  if(body == NULL) {
    trace(LOG_CRIT, "Unable to load config from %s -- %s", config_url,
          strerror(errno));
    close(fd);
    return -1;
  }

  if(read(fd, body, st.st_size) != st.st_size) {
    trace(LOG_CRIT, "Unable to load config from %s -- Read failed",
          config_url);
    close(fd);
    return -1;
  }
  close(fd);
  body[st.st_size] = 0;

  return config_apply(body, config_url);
}




#define EC2_METADATA "http://169.254.169.254/latest/meta-data/"

static void
ec2_apply_meta_data(void)
{
  scoped_char *instance_id =
    get_str_from_url(EC2_METADATA"instance-id");

  if(instance_id == NULL)
    return;
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
}



static int
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
    return -1;
  }

  trace(LOG_DEBUG, "Loaded metaconfig from %s", url);

  ntv_release(meta_config);
  meta_config = hcr.hcr_json_result;
  hcr.hcr_json_result = NULL;
  return 0;
}


static int
config_fns_cmp(const void *A, const void *B)
{
  const config_registration_t *a = A;
  const config_registration_t *b = B;
  return a->prio - b->prio;
}


void
config_init(const char *url)
{
  VEC_SORT(&config_update_fns, config_fns_cmp);

  const char *meta_config_url = NULL;

  const char *fl_env = getenv("FL_ENV");
  if(fl_env != NULL) {
    if(!strcmp(fl_env, "ec2")) {
      // We run under EC2
      ec2_apply_meta_data();
      meta_config_url = "http://169.254.169.254/latest/user-data";
    }
  }

  const char *mc = getenv("FL_META_CONFIG");
  if(mc != NULL)
    meta_config_url = mc;

  if(meta_config_url != NULL && strcmp(meta_config_url, "none"))
    load_metaconfig(meta_config_url);


  if(url == NULL) {
    // Allow URL to be overriden via environment arg
    url = getenv("FL_URL");
  }

  if(url != NULL) {
    ntv_release(meta_config);
    meta_config = ntv_map("url", ntv_str(url),
                          NULL);
  }
  trace(LOG_DEBUG, "Config initialized");
}

void
config_inhibit_updates(void)
{
  pthread_mutex_lock(&config_update_mutex);
  config_no_more_updates = 1;
  pthread_mutex_unlock(&config_update_mutex);
}



static void *
config_autoreloader(void *aux)
{
  while(1) {
    sleep(300);
    if(!atomic_get(&g_have_control_connection)) {
      trace(LOG_DEBUG, "Automatic config reload");
      config_reload();
    }
  }
  return NULL;
}


void
config_start_autoreloader(void)
{
  pthread_attr_t attr;
  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
  pthread_t tid;
  pthread_create(&tid, &attr, config_autoreloader, NULL);
  pthread_attr_destroy(&attr);
}
