#pragma once

void logging_early_init(void);

void logging_append(int pri, const char *procname, int pid, const char *msg);

TAILQ_HEAD(logline_queue, logline);
LIST_HEAD(logline_list, logline);
LIST_HEAD(logsink_list, logsink);

typedef struct logline {
  TAILQ_ENTRY(logline) link;
  LIST_ENTRY(logline) hash_link;
  char *procname;
  char *msg;
  unsigned int pid;
  unsigned int pri;
  uint64_t msgid;
  struct timeval tv;
} logline_t;

void logline_destroy(logline_t *l);

const char *logline_faclility_str(const logline_t *l);

typedef struct logsink {
  LIST_ENTRY(logsink) ls_global_link;
  LIST_ENTRY(logsink) ls_config_link;
  struct logline_queue ls_lines;

  int ls_num_loglines;
  int ls_num_loglines_dropped;
  int ls_level;
  int ls_mark;
  int ls_running;

  ntv_t *ls_conf;
  pthread_cond_t ls_cond;
  pthread_t ls_tid;


  const char *ls_errmsg;
  struct stream *ls_stream;

  // For syslog with ack
  struct logline_queue ls_sent_lines;
  struct logline_list *ls_ack_wait_hash;

} logsink_t;

extern pthread_mutex_t log_mutex;

logsink_t *logsink_find(const ntv_t *config, struct logsink_list *list);

logsink_t *logsink_create(const ntv_t *config, struct logsink_list *sinks);

void logsink_destroy(logsink_t *ls);

void logsinks_lock_mark(struct logsink_list *list);

void logsinks_sweep_unlock_reap(struct logsink_list *list);

