#include <pthread.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "config.h"

#include "libsvc/atomic.h"
#include "libsvc/vec.h"
#include "libsvc/ntv.h"
#include "libsvc/trace.h"
#include "libsvc/misc.h"
#include "libsvc/http_client.h"
#include "libsvc/strvec.h"

#include "cloud/aws.h"
#include "cloud/azure.h"

static ntv_t *g_meta_config;

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

int
config_apply(ntv_t *cfg, const char *source)
{
  pthread_mutex_lock(&config_update_mutex);
  if(config_no_more_updates) {
    pthread_mutex_unlock(&config_update_mutex);
    ntv_release(cfg);
    return 0;
  }

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

  pthread_mutex_unlock(&config_update_mutex);
  return 0;
}


int
config_apply_json(const char *json, const char *source)
{
  char errbuf[512];
  ntv_t *cfg = ntv_json_deserialize(json, errbuf, sizeof(errbuf));
  if(cfg == NULL) {
    trace(LOG_CRIT, "Unable to parse config from %s -- %s", source, errbuf);
    return -1;
  }
  return config_apply(cfg, source);
}





static int
config_reload_plain(const ntv_t *meta_config)
{
  char errbuf[512];
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

    return config_apply_json(hcr.hcr_body, config_url);
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

  return config_apply_json(body, config_url);
}


int
config_reload(void)
{
  if(g_meta_config == NULL) {
    trace(LOG_ERR, "No meta config set, nothing will happen");
    return -1;
  }

  const char *type = ntv_get_str(g_meta_config, "configSource") ?: "plain";
  if(!strcmp(type, "aws-sm")) {
    return aws_config_reload_sm(g_meta_config);
  } if(!strcmp(type, "plain")) {
    return config_reload_plain(g_meta_config);

  } else {
    trace(LOG_ERR, "Type '%s' meta config is unknown, nothing will happen",
          type);
    return -1;
  }

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

  const char *fl_env = getenv("FL_ENV");
  if(fl_env != NULL) {
    if(!strcmp(fl_env, "ec2")) {
      // We run under EC2
      g_meta_config = ec2_apply_meta_data();
    } else if(!strcmp(fl_env, "azure")) {
      // We run under EC2
      g_meta_config = azure_apply_meta_data();
    }
  }

  // Allow URL to be overriden via environment arg
  const char *override = getenv("FL_URL");
  if(override)
    url = override;

  if(url != NULL) {
    ntv_release(g_meta_config);
    g_meta_config = ntv_map("url", ntv_str(url),
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
