#pragma once

TAILQ_HEAD(logline_queue, logline);
LIST_HEAD(logline_list, logline);
LIST_HEAD(logsink_list, logsink);

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

typedef struct logsink {
  LIST_ENTRY(logsink) ls_global_link;
  LIST_ENTRY(logsink) ls_config_link;
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
  struct stream *ls_stream;

  // For syslog with ack
  struct logline_queue ls_sent_lines;
  struct logline_list *ls_ack_wait_hash;

} logsink_t;

void logging_early_init(void);
