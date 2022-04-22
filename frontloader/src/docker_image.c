#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>

#include "libsvc/ntv.h"
#include "libsvc/http_client.h"
#include "libsvc/misc.h"
#include "libsvc/talloc.h"
#include "libsvc/err.h"
#include "libsvc/trace.h"
#include "libsvc/murmur3.h"

#include "docker_image.h"
#include "fileutil.h"
#include "config.h"

static ntv_t *
tokenize_http_header(const char *input)
{
  scoped_char *copy = strdup(input);
  char *x = copy;
  ntv_t *map = ntv_create_map();
  int state = 0;
  const char *key = NULL;
  const char *value = NULL;
  while(*x) {
    char c = *x;
    switch(state) {
    case 0:  // Scanning for key
      if((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
        key = x;
        state = 1;
      }
      break;
    case 1:
      if(c == ' ' || c == '=') {
        *x = 0;
        state = 2;
      }
      break;
    case 2:
      if(c == '"' && x[1]) {
        value = x + 1;
        state = 3;
      }
      break;
    case 3:
      if(c == '"') {
        *x = 0;
        state = 0;
        ntv_set_str(map, key, value);
      }
      break;
    }
    x++;
  }
  return map;
}

static pthread_mutex_t auth_lock = PTHREAD_MUTEX_INITIALIZER;


static ntv_t *global_docker_config;


static int
docker_reconfigure(const ntv_t *config)
{
  const ntv_t *docker = ntv_get_map(config, "docker");

  pthread_mutex_lock(&auth_lock);
  ntv_release(global_docker_config);
  global_docker_config = ntv_copy(docker);
  pthread_mutex_unlock(&auth_lock);

  return 0;
}


CONFIG_SUB(docker_reconfigure, "docker", 10);

typedef struct docker_auth_aux {
  const ntv_t *docker_config;
  err_t **err;
} docker_auth_aux_t;



static const char *
docker_auth_cb(void *aux, int http_status, const char *authenticate)
{
#define DOCKER_TOKEN_CACHE_SIZE 32

  static struct {
    uint32_t uphash;
    char *token;
  } cache[DOCKER_TOKEN_CACHE_SIZE];

  const char *client_id = "frontloader";
  docker_auth_aux_t *daa = aux;
  char errbuf[512];

  pthread_mutex_lock(&auth_lock);

  const ntv_t *conf = daa->docker_config ?: global_docker_config;

  const char *username = ntv_get_str(conf, "username");
  const char *password = ntv_get_str(conf, "password");

  uint32_t hash = 1;

  if(username != NULL)
    hash = MurHash3_32(username, strlen(username), hash);
  if(password != NULL)
    hash = MurHash3_32(password, strlen(password), hash);

  const int bkt = hash % DOCKER_TOKEN_CACHE_SIZE;

  if(http_status == 0 && authenticate == NULL) {
    if(cache[bkt].uphash == hash && cache[bkt].token) {
      const char *r = tstrdup(cache[bkt].token);
      pthread_mutex_unlock(&auth_lock);
      return r;
    }
  }

  authenticate = authenticate ? mystrbegins(authenticate, "Bearer ") : NULL;

  if(authenticate == NULL) {
    pthread_mutex_unlock(&auth_lock);
    return NULL;
  }

  scoped_ntv_t *authmat = tokenize_http_header(authenticate);

  scoped_char *url = fmt("%s?service=%s&client_id=%s&scope=%s",
                         ntv_get_str(authmat, "realm"),
                         ntv_get_str(authmat, "service"),
                         client_id,
                         ntv_get_str(authmat, "scope"));
  scoped_http_result(result);

  int r = http_client_request(&result, url,
                              HCR_TIMEOUT(20),
                              HCR_USERNPASS(username, password),
                              HCR_ERRBUF(errbuf, sizeof(errbuf)),
                              HCR_FLAGS(HCR_DECODE_BODY_AS_JSON),
                              NULL);
  if(r) {
    err_push(daa->err, "Unable to auth: %s", errbuf);
    pthread_mutex_unlock(&auth_lock);
    return NULL;
  }

  const char *at = ntv_get_str(result.hcr_json_result, "access_token");
  if(at == NULL) {
    pthread_mutex_unlock(&auth_lock);
    return NULL;
  }

  const char *hdr = tsprintf("Bearer %s", at);
  cache[bkt].uphash = hash;
  strset(&cache[bkt].token, hdr);

  pthread_mutex_unlock(&auth_lock);
  return hdr;
}


/**
 *
 */
ntv_t *
docker_image_load_manifest(const char *manifest_url, err_t **err,
                           const ntv_t *docker_config)
{
  char *x0 = mystrdupa(manifest_url);
  // Decompose URL into docker repo + tag
  char *x1 = strstr(x0, "://");
  if(x1 == NULL) {
    err_push(err, "Invalid URL: %s", manifest_url);
    return NULL;
  }
  x1 += 3;
  x1 = strstr(x1, "/v2/");
  if(x1 == NULL) {
    err_push(err, "Docker repo URL %s is not /v2", manifest_url);
    return NULL;
  }

  x1 += 4;

  char *x2 = mystrdupa(x1);

  char *argv[4];
  if(str_tokenize(x2, argv, 4, '/') != 4) {
    err_push(err, "Malformed docker repo url: %s", manifest_url);
    return NULL;
  }

  *x1 = 0;

  char *repo_url = fmt("%s%s/%s", x0, argv[0], argv[1]);

  scoped_char *repo =
    strcmp(argv[0], "library") ? fmt("%s/%s", argv[0], argv[1]) : strdup(argv[1]);
  const char *tag = argv[3];

  docker_auth_aux_t daa = {
    .docker_config = docker_config,
    .err = err
  };

  scoped_http_result(result);
  int r = http_client_request(&result, manifest_url,
                              HCR_TIMEOUT(20),
                              HCR_ERR(err),
                              HCR_AUTHCB(docker_auth_cb, &daa),
                              HCR_FLAGS(HCR_DECODE_BODY_AS_JSON),
                              HCR_HEADER("Accept",
                                         "application/vnd.docker.distribution.manifest.v2+json"),
                              NULL);
  if(r) {
    err_push(err, "Unable to get docker manifest %s", manifest_url);
    return NULL;
  }
  const char *digest =
    ntv_get_str(result.hcr_headers, "docker-content-digest");
  digest = digest ? mystrbegins(digest, "sha256:") : NULL;
  if(digest == NULL) {
    err_push(err, "docker-content-digest header missing");
    return NULL;
  }

  return ntv_map("manifest", ntv_copy(result.hcr_json_result),
                 "digest", ntv_str(digest),
                 "repourl", ntv_str(repo_url),
                 "title", ntv_strf("%s:%s", repo, tag),
                 NULL);
}


static int
docker_image_install_with_cache(const char *basepath, const struct ntv *info,
                                const char *cachepath, docker_auth_aux_t *daa)
{
  const ntv_t *manifest = ntv_get_map(info, "manifest");
  const char *repo_url  = ntv_get_str(info, "repourl");

  const ntv_t *layers = ntv_get_list(manifest, "layers");
  int current_layer = 0;
  NTV_FOREACH_TYPE(layer, layers, NTV_MAP) {
    current_layer++;
    const char *digest = ntv_get_str(layer, "digest");

    scoped_char *cached_blob = fmt("%s/%s", cachepath, digest);
    FILE *fp = fopen(cached_blob, "rbe");
    if(fp != NULL) {
      if(!file_extract_from_FILE(fp, basepath, 1, 0, 1, daa->err)) {
        fclose(fp);
        continue;
      }
      fclose(fp);
      unlink(cached_blob);
    }

    if(mkdir_p(cachepath, 0755)) {
      err_pushsys(daa->err, "Unable to create %s", cachepath);
      return -1;
    }

    FILE *out = fopen(cached_blob, "wbe");
    if(out == NULL) {
      err_pushsys(daa->err, "Unable to create %s", cached_blob);
      return -1;
    }

    scoped_char *layer_url = fmt("%s/blobs/%s", repo_url, digest);

    scoped_http_result(hcr);

    if(http_client_request(&hcr, layer_url,
                           HCR_OUTPUTFILE(out),
                           HCR_ERR(daa->err),
                           HCR_AUTHCB(docker_auth_cb, daa),
                           NULL)) {
      fclose(out);
      err_pushsys(daa->err, "Unable to download %s to %s",
                  layer_url, cached_blob);
      return -1;
    }

    fclose(out);
    fp = fopen(cached_blob, "rbe");
    if(file_extract_from_FILE(fp, basepath, 1, 0, 1, daa->err)) {
      err_push(daa->err, "Unable to extract layer %s", layer_url);
      fclose(fp);
      return -1;
    }
    fclose(fp);
  }
  return 0;
}




int
docker_image_install(const char *basepath, const struct ntv *info,
                     struct err **err, const ntv_t *docker_config)
{
  const char *cachepath = NULL; // cfg_get_str(cr, CFG("docker", "cache"), NULL);

  docker_auth_aux_t daa = {
    .docker_config = docker_config,
    .err = err
  };

  if(cachepath != NULL)
    return docker_image_install_with_cache(basepath, info, cachepath, &daa);

  const ntv_t *manifest = ntv_get_map(info, "manifest");
  const char *repo_url  = ntv_get_str(info, "repourl");

  const ntv_t *layers = ntv_get_list(manifest, "layers");
  int current_layer = 0;
  NTV_FOREACH_TYPE(layer, layers, NTV_MAP) {
    current_layer++;
    const char *digest = ntv_get_str(layer, "digest");
    scoped_char *layer_url = fmt("%s/blobs/%s", repo_url, digest);

    FILE *fp = http_read_file(layer_url, &daa, docker_auth_cb, 0);
    if(fp == NULL) {
      err_push(err, "Unable to download layer %s", layer_url);
      return -1;
    }
    if(file_extract_from_FILE(fp, basepath, 1, 0, 1, err)) {
      err_push(err, "Unable to extract layer %s", layer_url);
      fclose(fp);
      return -1;
    }
    fclose(fp);
  }
  return 0;
}

ntv_t *
docker_image_get_config(const struct ntv *info, struct err **err,
                        const ntv_t *docker_config)
{
  const ntv_t *manifest = ntv_get_map(info, "manifest");
  const char *repo_url  = ntv_get_str(info, "repourl");
  const ntv_t *config   = ntv_get_map(manifest, "config");
  const char *digest    = ntv_get_str(config, "digest");
  scoped_char *config_url = fmt("%s/blobs/%s", repo_url, digest);

  docker_auth_aux_t daa = {
    .docker_config = docker_config,
    .err = err
  };

  scoped_http_result(result);
  int r = http_client_request(&result, config_url,
                              HCR_TIMEOUT(20),
                              HCR_ERR(err),
                              HCR_AUTHCB(docker_auth_cb, &daa),
                              HCR_FLAGS(HCR_DECODE_BODY_AS_JSON),
                              HCR_HEADER("Accept",
                                         "application/vnd.docker.container.image.v1+json"),
                              NULL);
  if(r)
    return NULL;

  ntv_t *s = result.hcr_json_result;
  result.hcr_json_result = NULL;
  return s;
}
