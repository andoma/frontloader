#include <errno.h>
#include <sys/mman.h>
#include <pthread.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>

#include <openssl/hmac.h>
#include <openssl/sha.h>

#include "libsvc/misc.h"
#include "libsvc/talloc.h"
#include "libsvc/ntv.h"
#include "libsvc/err.h"
#include "libsvc/http_client.h"
#include "libsvc/tcp.h"
#include "libsvc/trace.h"
#include "libsvc/strvec.h"
#include "libsvc/init.h"
#include "libsvc/aws.h"

#include "coreupload.h"
#include "config.h"

#define HTTP_CLIENT_FLAGS 0 // HCR_VERBOSE

#define NUM_ATTEMPTS 10


/**
 *
 */
static char *
s3_make_url(const char *verb,
            const char *object,
            const char *region,
            const char *bucket,
            int uploads,
            const char *upload_id,
            const char *part_number)
{
  scoped_ntv_t *query_args = ntv_map("uploadId", ntv_str(upload_id),
                                     "partNumber", ntv_str(part_number),
                                     "uploads", uploads ? ntv_str("") : NULL,
                                     NULL);

  return aws_s3_make_url(verb, region, bucket, object,
                         aws_get_creds(), query_args);
}


static char *
get_upload_id(const char *object, const char *region,
              const char *bucket)
{
  int attempts = 0;
  while(1) {
    scoped_err_t *err = NULL;
    scoped_http_result(result);

    scoped_char *url =
      s3_make_url("POST", object, region, bucket, 1, NULL, NULL);
    int r = http_client_request(&result, url,
                                HCR_FLAGS(HTTP_CLIENT_FLAGS),
                                HCR_ERR(&err),
                                HCR_VERB("POST"),
                                NULL);
    if(!r) {
      const char *tag    = strstr(result.hcr_body, "<UploadId>");
      const char *endtag = strstr(result.hcr_body, "</UploadId>");

      if(tag == NULL || endtag == NULL || tag > endtag) {
        syslog(LOG_ALERT, "Core upload to %s failed, unable to parse XML",
               object);
        return NULL;
      }
      tag += strlen("<UploadId>");
      size_t s = endtag - tag;
      char *uploadid = malloc(s + 1);
      memcpy(uploadid, tag, s);
      uploadid[s] = 0;
      return uploadid;
    }

    if(++attempts == NUM_ATTEMPTS) {
      scoped_char *errstr = err_str(err);
      syslog(LOG_ALERT, "Core upload to %s failed, unable to get object id %s",
             object, errstr);
      return NULL;
    }
    sleep(attempts);
  }
}


static char *
upload_part(const char *object, const char *region,
            const char *bucket,
            const char *upload_id, int part_number,
            const void *buffer, size_t part_size)
{
  char part_number_str[64];
  snprintf(part_number_str, sizeof(part_number_str), "%d", part_number);

  int attempts = 0;
  while(1) {
    scoped_char *url =
      s3_make_url("PUT", object, region, bucket, 0, upload_id, part_number_str);

    scoped_err_t *err = NULL;
    scoped_http_result(result);
    int r = http_client_request(&result, url,
                                HCR_FLAGS(HTTP_CLIENT_FLAGS),
                                HCR_ERR(&err),
                                HCR_PUTDATA(buffer, part_size,
                                            "application/octet-stream"),
                                NULL);
    if(!r) {
      const char *etag = ntv_get_str(result.hcr_headers, "etag");
      return etag ? strdup(etag) : NULL;
    }

    if(++attempts == NUM_ATTEMPTS) {
      char *errstr = err_str(err);
      syslog(LOG_ALERT, "Core upload to %s failed, unable upload part %d -- %s",
             object, part_number, errstr);
      return NULL;
    }
    sleep(attempts);
  }
}





static int
complete_upload(const char *object, const char *region,
                const char *bucket, const char *upload_id,
                const strvec_t *etags)
{

  scoped_mbuf_t bodybuf = MBUF_INITIALIZER(bodybuf);

  mbuf_append_str(&bodybuf, "<CompleteMultipartUpload>");
  for(int i = 0; i < etags->count; i++) {
    scoped_char *s =
      fmt("<Part><PartNumber>%d</PartNumber><ETag>%s</ETag></Part>",
          i + 1, strvec_get(etags, i));
    mbuf_append_str(&bodybuf, s);
  }
  mbuf_append_str(&bodybuf, "</CompleteMultipartUpload>");

  const void *body = mbuf_pullup(&bodybuf, bodybuf.mq_size);

  int attempts = 0;
  while(1) {
    scoped_char *url =
      s3_make_url("POST", object, region, bucket, 0, upload_id, NULL);

    scoped_err_t *err = NULL;
    scoped_http_result(result);
    int r = http_client_request(&result, url,
                                HCR_FLAGS(HTTP_CLIENT_FLAGS),
                                HCR_ERR(&err),
                                HCR_POSTDATA(body, bodybuf.mq_size,
                                             "application/xml"),
                                NULL);

    if(!r)
      return 0;

    if(++attempts == NUM_ATTEMPTS) {
      char *errstr = err_str(err);
      syslog(LOG_ALERT, "Core upload to %s failed, unable to complete upload -- %s",
             object, errstr);
      return -1;
    }
  }
  return 0;
}



static int
upload_file(const char *object, const char *region,
            const char *bucket,
            const void *buffer, size_t part_size)
{
  int attempts = 0;
  while(1) {
    scoped_char *url =
      s3_make_url("PUT", object, region, bucket, 0, NULL, NULL);

    scoped_err_t *err = NULL;
    scoped_http_result(result);
    int r = http_client_request(&result, url,
                                HCR_FLAGS(HTTP_CLIENT_FLAGS),
                                HCR_ERR(&err),
                                HCR_PUTDATA(buffer, part_size,
                                            "application/octet-stream"),
                                NULL);
    if(!r)
      return 0;

    if(++attempts == NUM_ATTEMPTS) {
      char *errstr = err_str(err);
      syslog(LOG_ALERT, "Core upload to %s failed -- %s",
             object, errstr);
      return -1;
    }
    sleep(1);
  }
  return 0;
}



TAILQ_HEAD(part_queue, part);


static struct part_queue pending_parts;

static pthread_mutex_t part_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t part_new_cond = PTHREAD_COND_INITIALIZER;
static pthread_cond_t part_done_cond = PTHREAD_COND_INITIALIZER;

static int parts_pending;

typedef struct part {
  TAILQ_ENTRY(part) p_link;
  TAILQ_ENTRY(part) p_work_link;

  const char *p_object;
  const char *p_region;

  const char *p_bucket;

  const char *p_upload_id;

  int p_part_number;
  void *p_buffer;
  size_t p_size;
  size_t p_mapped_size;
  char *p_etag;
} part_t;



static void *
uploader_worker(void *aux)
{
  part_t *p;
  pthread_mutex_lock(&part_mutex);
  while(1) {

    p = TAILQ_FIRST(&pending_parts);
    if(p == NULL) {
      pthread_cond_wait(&part_new_cond, &part_mutex);
      continue;
    }

    parts_pending++;
    TAILQ_REMOVE(&pending_parts, p, p_work_link);
    pthread_mutex_unlock(&part_mutex);

    char *tag =
      upload_part(p->p_object, p->p_region, p->p_bucket,
                  p->p_upload_id,
                  p->p_part_number, p->p_buffer, p->p_size);

    munmap(p->p_buffer, p->p_mapped_size);
    pthread_mutex_lock(&part_mutex);
    p->p_etag = tag;
    parts_pending--;
    pthread_cond_signal(&part_done_cond);
  }

  return NULL;
}



int
coreupload(int argc, char **argv)
{
  int c;
  const char *cfgfile = NULL;
  const char *path = NULL;
  while((c = getopt(argc, argv, "c:p:")) != -1) {
    switch(c) {
    case 'c':
      cfgfile = optarg;
      break;
    case 'p':
      path = optarg;
      break;
    }
  }

  tcp_init(NULL);

  openlog("coreupload", LOG_PID, LOG_DAEMON);

  if(cfgfile == NULL) {
    syslog(LOG_ALERT, "Not uploading upload core %s -- No config specified", path);
    return 1;
  }

  char *json = readfile(cfgfile, NULL);
  if(json == NULL) {
    syslog(LOG_ALERT, "Not uploading upload core %s -- Config %s can't be read",
           path, cfgfile);
    return 1;
  }

  const ntv_t *cfg = ntv_json_deserialize(json, NULL, 0);
  if(cfg == NULL) {
    syslog(LOG_ALERT, "Failed to upload core %s -- Config %s can't be parsed",
           path, cfgfile);
    return 1;
  }

  const char *region   = ntv_get_str(cfg, "region");
  const char *bucket   = ntv_get_str(cfg, "bucket");
  const int upload_parallelism = ntv_get_int(cfg, "parallelism", 3);

  if(region == NULL || bucket == NULL) {
    syslog(LOG_ALERT, "Failed to upload core %s -- Config %s missing keys",
           path, cfgfile);
    return 1;
  }

  scoped_err_t *err = NULL;

  const char *object = fmt("/%s", path);

  const char *upload_id = NULL;

  syslog(LOG_WARNING, "Starting core upload to %s", object);

  struct part_queue all_parts;
  TAILQ_INIT(&all_parts);
  TAILQ_INIT(&pending_parts);


  pthread_attr_t attr;
  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
  pthread_t tid;
  pthread_attr_destroy(&attr);

  for(int i = 0; i < upload_parallelism; i++) {
    pthread_create(&tid, &attr, uploader_worker, NULL);
  }

  const size_t max_part_size = 1024 * 1024 * 10;
  int part_number = 1;

  while(!feof(stdin)) {

    char *part_buf;

    while((part_buf = mmap(NULL, max_part_size, PROT_READ | PROT_WRITE,
                           MAP_POPULATE | MAP_PRIVATE | MAP_ANONYMOUS,
                           -1, 0)) == MAP_FAILED) {
      const int saved_errno = errno;
      pthread_mutex_lock(&part_mutex);

      if(parts_pending) {
        pthread_cond_wait(&part_done_cond, &part_mutex);
        pthread_mutex_unlock(&part_mutex);
        continue;
      }

      syslog(LOG_ALERT, "Failed to upload core %s -- %s", object,
             strerror(saved_errno));
      exit(1);
    }

    size_t r = fread(part_buf, 1, max_part_size, stdin);
    if(r == 0)
      break;

    if(part_number == 1 && r < max_part_size) {
      // Part is small enough for a normal upload

      if(upload_file(object, region, bucket, part_buf, r))
        return 1;
      syslog(LOG_ALERT, "Core uploaded to %s", object);
      return 0;
    }

    if(upload_id == NULL) {
      upload_id = get_upload_id(object, region, bucket);
      if(upload_id == NULL)
        return 1;
    }

    part_t *p = calloc(1, sizeof(part_t));
    p->p_object = object;
    p->p_region = region;
    p->p_bucket = bucket;
    p->p_upload_id = upload_id;

    p->p_part_number = part_number;
    p->p_buffer = part_buf;
    p->p_mapped_size = max_part_size;
    p->p_size = r;

    TAILQ_INSERT_TAIL(&all_parts, p, p_link);

    pthread_mutex_lock(&part_mutex);
    pthread_cond_signal(&part_new_cond);
    TAILQ_INSERT_TAIL(&pending_parts, p, p_work_link);
    pthread_mutex_unlock(&part_mutex);
    part_number++;
  }

  pthread_mutex_lock(&part_mutex);
  while(TAILQ_FIRST(&pending_parts) != NULL || parts_pending)
    pthread_cond_wait(&part_done_cond, &part_mutex);
  pthread_mutex_unlock(&part_mutex);

  scoped_strvec(etags);
  part_t *p;
  TAILQ_FOREACH(p, &all_parts, p_link) {
    strvec_push(&etags, p->p_etag);
  }

  if(complete_upload(object, region, bucket, upload_id, &etags))
    return 1;

  syslog(LOG_ALERT, "Core uploaded to %s", object);
  return 0;
}





static int
coreupload_reconfigure(const ntv_t *cr)
{
  const ntv_t *config = ntv_get_map(cr, "coreuploader");
  const char *pattern = ntv_get_str(config, "pattern");

  const char *cfgfile = "/var/run/coredumper.json";

  if(pattern == NULL) {
    unlink(cfgfile);
    return 0;
  }
  scoped_char *json = ntv_json_serialize_to_str(config, 0);

  writefile(cfgfile, json, strlen(json), 0);

  FILE *fp = fopen("/proc/sys/kernel/core_pattern", "we");
  if(fp == NULL)
    return 0;
  fprintf(fp, "|/usr/bin/coreuploader -p %s -c %s", pattern, cfgfile);
  fclose(fp);
  return 0;
}

CONFIG_SUB(coreupload_reconfigure, "coreupload", 2000);
