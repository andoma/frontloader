#define _GNU_SOURCE
#include <sys/socket.h>
#include <sys/un.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <stdio.h>
#include <stdarg.h>
#include <syslog.h>

#include "libsvc/init.h"
#include "libsvc/misc.h"
#include "libsvc/trace.h"
#include "libsvc/ntv.h"
#include "libsvc/stream.h"
#include "libsvc/mbuf.h"
#include "libsvc/atomic.h"

#include "config.h"
#include "logging.h"
#include "stats.h"

static atomic_t stats_log_sent;
static atomic_t stats_acks_rcvd;
static atomic_t stats_acks_bad;

#define LOG_ROTATE_SIZE 500000



TAILQ_HEAD(logline_queue, logline);
LIST_HEAD(logline_list, logline);

struct logline {
  TAILQ_ENTRY(logline) link;
  LIST_ENTRY(logline) hash_link;
  char *procname;
  char *msg;
  int pid;
  int pri;
  uint64_t msgid;
  struct timeval tv;
};

#define MAX_LOGLINES_IN_RAM 10000

#define ACK_WAIT_HASH_SIZE 2048
#define ACK_WAIT_HASH_MASK (ACK_WAIT_HASH_SIZE - 1)

static LIST_HEAD(, logsink) logsinks;

typedef struct logsink {
  LIST_ENTRY(logsink) ls_link;
  struct logline_queue ls_lines;
  int ls_num_loglines;
  int ls_num_loglines_dropped;
  ntv_t *ls_conf;
  int ls_level;
  pthread_cond_t ls_cond;
  int ls_mark;
  pthread_t ls_tid;
  int ls_running;

  const char *ls_errmsg;
  stream_t *ls_stream;

  // For syslog with ack
  struct logline_queue ls_sent_lines;
  struct logline_list *ls_ack_wait_hash;

} logsink_t;


static int logdir;
static int syslogfd = -1;
static int devconsole = -1;
static int logfilesize;
static int log_system_completed;
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct logline_queue early_loglines;
static int num_early_loglines;

static uint64_t msgid_generator;

static const char months[12][4] = {
  "Jan", "Feb", "Mar", "Apr", "May", "Jun",
  "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
};

static const char *facilities[] = {
  "kernel",
  "user",
  "mail",
  "daemon",
  "security",
  "syslog",
  "lps",
  "news",
  "uucp",
  "clock",
  "security",
  "ftp",
  "ntp",
  "audit",
  "alert",
  "clock",
  "local0",
  "local1",
  "local2",
  "local3",
  "local4",
  "local5",
  "local6",
  "local7",
};


static void
send_logline(struct timeval *tv, int pid, int pri,
             const char *procname, const char *msg)
{
  uint64_t msgid = ++msgid_generator;
  logsink_t *ls;
  const int level = pri & 7;
  LIST_FOREACH(ls, &logsinks, ls_link) {
    if(level > ls->ls_level)
      continue; // Skip levels that are higher than the configured limit
    if(ls->ls_num_loglines >= MAX_LOGLINES_IN_RAM) {
      ls->ls_num_loglines_dropped++;
    } else {
      struct logline *l = malloc(sizeof(struct logline));
      l->tv = *tv;
      l->pid = pid;
      l->pri = pri;
      l->procname = strdup(procname);
      l->msgid = msgid;
      l->msg = strdup(msg);
      TAILQ_INSERT_TAIL(&ls->ls_lines, l, link);
      ls->ls_num_loglines++;
      pthread_cond_signal(&ls->ls_cond);
    }
  }
}

static void
send_early_loglines(void)
{
  struct logline *l;
  while((l = TAILQ_FIRST(&early_loglines)) != NULL) {
    TAILQ_REMOVE(&early_loglines, l, link);
    send_logline(&l->tv, l->pid, l->pri, l->procname, l->msg);
    free(l->msg);
    free(l->procname);
    free(l);
  }
  num_early_loglines = 0;
}


static void
writelog(int pri, const char *procname, int pid, const char *msg)
{
  const int level = pri & 7;
  scoped_char *line = NULL;
  struct timeval tv;
  gettimeofday(&tv, NULL);
  struct tm tm;
  localtime_r(&tv.tv_sec, &tm);

  if(procname == NULL) {
    const int fac = pri >> 3;
    if(fac > 23) {
      procname = "unknown";
    } else {
      procname = facilities[fac];
    }
  }

  if(pid == 0) {
    line = fmt("%s %2d %02d:%02d:%02d %s: %s\n",
               months[tm.tm_mon], tm.tm_mday,
               tm.tm_hour, tm.tm_min, tm.tm_sec,
               procname, msg);
  } else {
    line = fmt("%s %2d %02d:%02d:%02d %s[%d]: %s\n",
               months[tm.tm_mon], tm.tm_mday,
               tm.tm_hour, tm.tm_min, tm.tm_sec,
               procname, pid, msg);
  }

  if(level <= LOG_CRIT && devconsole != -1) {
    dprintf(devconsole, "LOG: %s", line);
  }

  pthread_mutex_lock(&log_mutex);


  if(logfilesize >= LOG_ROTATE_SIZE) {
    close(syslogfd);
    renameat(logdir, "syslog", logdir, "syslog.0");
    syslogfd = -1;
  }

  if(syslogfd == -1 && logdir != -1) {
    syslogfd = openat(logdir, "syslog", O_TRUNC | O_CREAT | O_WRONLY, 0644);
    if(syslogfd != -1) {
      logfilesize = 0;
    }
  }

  if(syslogfd != -1) {
    int r = write(syslogfd, line, strlen(line));
    if(r < 0)
      printf("syslog error -- %s", strerror(errno));
    else
      logfilesize += r;
  }

  if(log_system_completed) {
    send_logline(&tv, pid, pri, procname, msg);
  } else if(num_early_loglines < 10000) {
    struct logline *l = malloc(sizeof(struct logline));
    l->tv = tv;
    l->pid = pid;
    l->pri = pri;
    l->procname = strdup(procname);
    l->msg = strdup(msg);
    TAILQ_INSERT_TAIL(&early_loglines, l, link);
    num_early_loglines++;
  }

  pthread_mutex_unlock(&log_mutex);
}







static int
open_devlog(void)
{
  const char *path = "/dev/log";

  unlink(path);

  int fd = socket(AF_LOCAL, SOCK_DGRAM|SOCK_CLOEXEC, 0);
  if(fd == -1) {
    perror("devlog socket");
    return -1;
  }

  struct sockaddr_un sun = {.sun_family = AF_LOCAL};
  strcpy(sun.sun_path, path);

  if(bind(fd, (struct sockaddr *)&sun, sizeof(sun)) == -1) {
    perror("devlog bind");
    close(fd);
    return -1;
  }

  chmod(path, 0777);

  return fd;

}



static int
parse_process(int pri, char *s)
{
  char *procname = s;
  while(*s != 0 && *s != '[' && *s != ' ')
    s++;
  if(*s != '[')
    return 1;
  char *c1 = s;
  s++;
  int pid = atoi(s);
  while(*s >= '0' && *s <= '9')
    s++;
  if(memcmp(s, "]: ", 3))
    return 1;
  s += 3;
  *c1 = 0;
  writelog(pri, procname, pid, s);
  return 0;
}




static void *
devlog_thread(void *aux)
{
  int fd = (intptr_t)aux;
  char buf[65536];
  while(1) {
    int r = read(fd, buf, sizeof(buf) - 1);

    if(r < 0) {
      perror("devlog read error");
      close(fd);
      sleep(1);
      fd = open_devlog();
      if(fd == -1) {
        return NULL;
      }
      continue;
    }

    buf[r] = 0;
    while(r > 0 && buf[r - 1] < 32)
      buf[--r] = 0;

    int pri = LOG_DEBUG;
    char *m = buf;

    pri = LOG_INFO;
    if(*m == '<') {
      m++;
      if(*m)
        pri = strtoul(m, &m, 10);
      if(*m == '>')
        m++;
    }

    if(strlen(m) > 16 && m[3] == ' ' && m[6] == ' ' && m[9] == ':') {
      m += 16;
    }

    if(parse_process(pri, m)) {
      writelog(pri, NULL, 0, m);
    }
  }

  return NULL;
}


static void
devlog_init(void)
{
  int fd = open_devlog();
  if(fd == -1)
    return;

  pthread_t tid;
  pthread_attr_t attr;

  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

  pthread_create(&tid, &attr, devlog_thread, (void *)(intptr_t)fd);
}



static void *
klog_thread(void *aux)
{
  int fd = (intptr_t)aux;
  char buf[1024] = {};
  int len = 0;
  while(1) {
    int r = read(fd, buf + len, sizeof(buf) - len);

    if(r < 0) {
      perror("klog read error");
      close(fd);
      return NULL;
    }
    len += r;
  again:
    for(int i = 0; i < len; i++) {
      if(buf[i] == '\n') {
        buf[i] = 0;

        int pri = LOG_DEBUG;
        char *m = buf;

        pri = LOG_INFO;
        if(*m == '<') {
          m++;
          if(*m)
            pri = strtoul(m, &m, 10);
          if(*m == '>')
            m++;
        }

        writelog(pri, "kernel", 0, m);

        i++;
        memmove(buf, buf + i, len - i);
        len -= i;
        goto again;
      }
    }
  }
  return NULL;
}

static void
klog_init(void)
{
  int fd = open("/proc/kmsg", O_RDONLY | O_CLOEXEC);
  if(fd == -1) {
    perror("open /proc/kmsg");
    return;
  }

  pthread_t tid;
  pthread_attr_t attr;
  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
  pthread_create(&tid, &attr, klog_thread, (void *)(intptr_t)fd);
}



static void *
recv_ack_thread(void *aux)
{
  logsink_t *ls = aux;
  uint8_t buf[512];

  scoped_mbuf_t linebuf = MBUF_INITIALIZER(linebuf);
  while(1) {
    ssize_t r = stream_read(ls->ls_stream, buf, sizeof(buf), 0);
    if(r < 1)
      break;

    mbuf_append(&linebuf, buf, r);

    int len;
    while((len = mbuf_find(&linebuf, '\n')) != -1) {
      char line[len + 1];
      mbuf_read(&linebuf, line, len);
      line[len] = 0;
      mbuf_drop(&linebuf, 1);

      const uint64_t id = strtoull(line, NULL, 10);
      atomic_inc(&stats_acks_rcvd);

      pthread_mutex_lock(&log_mutex);

      const uint32_t bucket = id & ACK_WAIT_HASH_MASK;

      struct logline *l;
      LIST_FOREACH(l, ls->ls_ack_wait_hash + bucket, hash_link) {
        if(l->msgid == id)
          break;
      }

      if(l != NULL) {
        TAILQ_REMOVE(&ls->ls_sent_lines, l, link);
        LIST_REMOVE(l, hash_link);
        ls->ls_num_loglines--;
        free(l->msg);
        free(l->procname);
        free(l);
      } else {
        atomic_inc(&stats_acks_bad);
      }
      pthread_mutex_unlock(&log_mutex);
    }
  }

  pthread_mutex_lock(&log_mutex);
  if(ls->ls_errmsg == NULL) {
    ls->ls_errmsg = "Read error";
    pthread_cond_signal(&ls->ls_cond);
  }
  pthread_mutex_unlock(&log_mutex);
  return NULL;
}


static void *
remote_syslog_thread(void *aux)
{
  logsink_t *ls = aux;
  pthread_t ack_tid;
  char hostname[128] = {};
  char errbuf[512];
  struct logline *l;

  const char *host = ntv_get_str(ls->ls_conf, "hostname");
  const char *format = ntv_get_str(ls->ls_conf, "format");
  if(host == NULL || format == NULL)
    return NULL;
  const int tls = ntv_get_int(ls->ls_conf, "tls", 0);
  const int port = ntv_get_int(ls->ls_conf, "port", 514);
  const int use_ack = ntv_get_int(ls->ls_conf, "ack", 0);

  if(use_ack) {
    ls->ls_ack_wait_hash = malloc(sizeof(struct logline_list) *
                                  ACK_WAIT_HASH_SIZE);
  }

  while(1) {
    stream_t *s = stream_connect(host, port, 5000, errbuf, sizeof(errbuf),
                                 tls ? STREAM_CONNECT_F_SSL : 0);
    if(s == NULL) {
      trace(LOG_WARNING, "syslog: Unable to connect to %s:%d -- %s", host, port, errbuf);

      for(int i = 0; i < 30; i++) {
        if(!ls->ls_running) {
          return NULL;
        }
        sleep(1);
      }
      continue;
    }
    trace(LOG_DEBUG, "syslog: Connected to %s:%d", host, port);

    if(gethostname(hostname, sizeof(hostname) - 1))
      strcpy(hostname, "badhostname");


    ls->ls_stream = s;
    ls->ls_errmsg = NULL;

    if(use_ack) {
      memset(ls->ls_ack_wait_hash, 0,
             sizeof(struct logline_list) * ACK_WAIT_HASH_SIZE);
      pthread_create(&ack_tid, NULL, recv_ack_thread, ls);
    }

    pthread_mutex_lock(&log_mutex);

    while(ls->ls_errmsg == NULL && ls->ls_running) {
      l = TAILQ_FIRST(&ls->ls_lines);
      if(l == NULL) {
        pthread_cond_wait(&ls->ls_cond, &log_mutex);
        continue;
      }
      TAILQ_REMOVE(&ls->ls_lines, l, link);
      pthread_mutex_unlock(&log_mutex);

      struct tm tm;
      localtime_r(&l->tv.tv_sec, &tm); // We are always in UTC

      char pri_str[16];
      snprintf(pri_str, sizeof(pri_str), "%d", l->pri);

      char pid_str[16];
      snprintf(pid_str, sizeof(pid_str), "%d", l->pid);

      char msgid_str[16];
      snprintf(msgid_str, sizeof(msgid_str), "%"PRIu64, l->msgid);

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

      const char *tokens[] = {
        "PRI", pri_str,
        "RFC3339DATE", rfc3339_date,
        "HOSTNAME", hostname,
        "PROCESS", l->procname,
        "PID", pid_str,
        "MSG", l->msg,
        "MSGID", msgid_str,
        NULL
      };

      char *output = str_replace_tokens(fmt("%s\n", format), "${", "}", tokens);

      int len = strlen(output);
      int ret = stream_write(s, output, len);
      atomic_inc(&stats_log_sent);
      pthread_mutex_lock(&log_mutex);

      if(ret != len)
        ls->ls_errmsg = ret < 0 ? strerror(errno) : "Write failed";

      free(output);


      if(use_ack) {
        const uint32_t bucket = l->msgid & ACK_WAIT_HASH_MASK;
        TAILQ_INSERT_TAIL(&ls->ls_sent_lines, l, link);
        LIST_INSERT_HEAD(ls->ls_ack_wait_hash + bucket, l, hash_link);
      } else {
        ls->ls_num_loglines--;
        free(l->msg);
        free(l->procname);
        free(l);
      }
    }

    if(use_ack) {
      // Reinsert all sent lines into the main queue (at front)
      TAILQ_MERGE(&ls->ls_sent_lines, &ls->ls_lines, link);
      TAILQ_MOVE(&ls->ls_lines, &ls->ls_sent_lines, link);
    }

    stream_shutdown(s);

    if(use_ack) {
      pthread_mutex_unlock(&log_mutex);
      pthread_join(ack_tid, NULL);
      pthread_mutex_lock(&log_mutex);
    }

    stream_close(s);

    trace(LOG_DEBUG, "syslog: Disconnected from %s:%d -- %s (%d messages not delivered)",
          host, port, ls->ls_errmsg ?: "No error", ls->ls_num_loglines);

    if(!ls->ls_running) {
      pthread_mutex_unlock(&log_mutex);
      return NULL;
    }

    pthread_mutex_unlock(&log_mutex);
  }
  return NULL;
}




void
logging_early_init(void)
{
  TAILQ_INIT(&early_loglines);
  logdir = open("/var/log", O_PATH | O_CLOEXEC);
  devconsole = open("/dev/console", O_WRONLY);
  klog_init();
  devlog_init();
}


static logsink_t *
logsink_find(const ntv_t *config)
{
  logsink_t *ls;
  LIST_FOREACH(ls, &logsinks, ls_link) {
    if(!ntv_cmp(ls->ls_conf, config))
      return ls;
  }
  return NULL;
}


static logsink_t *
logsink_create(const ntv_t *config)
{
  logsink_t *ls = calloc(1, sizeof(logsink_t));
  TAILQ_INIT(&ls->ls_lines);
  TAILQ_INIT(&ls->ls_sent_lines);
  LIST_INSERT_HEAD(&logsinks, ls, ls_link);
  pthread_cond_init(&ls->ls_cond, NULL);
  ls->ls_conf = ntv_copy(config);
  ls->ls_level = ntv_get_int(config, "level", 7);
  ls->ls_running = 1;
  return ls;
}

static void
logsink_destroy(logsink_t *ls)
{
  struct logline *l;
  while((l = TAILQ_FIRST(&ls->ls_lines)) != NULL) {
    TAILQ_REMOVE(&ls->ls_lines, l, link);
    free(l->msg);
    free(l->procname);
    free(l);
  }
  ntv_release(ls->ls_conf);
  free(ls->ls_ack_wait_hash);
  free(ls);
}


static int
logging_reconfigure(const ntv_t *cfg)
{
  const ntv_t *cfged_sinks = ntv_get_list(cfg, "logsinks");
  // Handle reset of logsetup now that we have config

  pthread_mutex_lock(&log_mutex);

  logsink_t *ls;
  LIST_FOREACH(ls, &logsinks, ls_link) {
    ls->ls_mark = 1;
  }

  if(cfged_sinks != NULL) {

    NTV_FOREACH_TYPE(l, cfged_sinks, NTV_MAP) {

      logsink_t *ls = logsink_find(l);
      if(ls != NULL) {
        ls->ls_mark = 0;
        continue;
      }

      const char *type = ntv_get_str(l, "type");
      if(!strcmp(type, "syslog")) {
        ls = logsink_create(l);
        pthread_create(&ls->ls_tid, NULL, remote_syslog_thread, ls);
      }
    }
  }
  log_system_completed = 1;
  send_early_loglines();

  LIST_HEAD(, logsink) logsink_reap_list;
  LIST_INIT(&logsink_reap_list);

  logsink_t *n;
  for(ls = LIST_FIRST(&logsinks); ls != NULL; ls = n) {
    n = LIST_NEXT(ls, ls_link);
    if(!ls->ls_mark)
      continue;
    ls->ls_running = 0;
    pthread_cond_signal(&ls->ls_cond);
    LIST_REMOVE(ls, ls_link);
    LIST_INSERT_HEAD(&logsink_reap_list, ls, ls_link);
  }
  pthread_mutex_unlock(&log_mutex);

  while((ls = LIST_FIRST(&logsink_reap_list)) != NULL) {
    pthread_join(ls->ls_tid, NULL);
    LIST_REMOVE(ls, ls_link);
    logsink_destroy(ls);
  }

  return 0;
}

CONFIG_SUB(logging_reconfigure, "logging", 10);



static void
stats_log(struct ntv *gauges, struct ntv *rates)
{
  return;

  ntv_set(rates, "lb.frontloader.syslog_sent",
          atomic_get_and_set(&stats_log_sent, 0));
  ntv_set(rates, "lb.frontloader.syslog_acks_rcvd",
          atomic_get_and_set(&stats_acks_rcvd, 0));
  ntv_set(rates, "lb.frontloader.syslog_acks_bad",
          atomic_get_and_set(&stats_acks_bad, 0));
}



GSTATS(stats_log);
