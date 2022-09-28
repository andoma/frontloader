#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>

#include "libsvc/atomic.h"
#include "libsvc/misc.h"
#include "libsvc/ntv.h"
#include "libsvc/websocket_client.h"
#include "libsvc/websocket.h"
#include "libsvc/trace.h"
#include "libsvc/http_parser.h"

#include "config.h"


static pthread_mutex_t ctrl_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t ctrl_cond = PTHREAD_COND_INITIALIZER;

static char *ctrl_wanted_url;
static ws_client_t *ctrl_con;


atomic_t g_have_control_connection;

static void
disconnect(void)
{
  pthread_mutex_lock(&ctrl_mutex);

  if(ctrl_con != NULL) {
    atomic_set(&g_have_control_connection, 0);
    ws_client_destroy(ctrl_con);
    ctrl_con = NULL;
    pthread_cond_signal(&ctrl_cond);
  }
  pthread_mutex_unlock(&ctrl_mutex);
}


static void
control_input_json(const char *buf)
{
  char errbuf[512];
  scoped_ntv_t *msg = ntv_json_deserialize(buf, errbuf, sizeof(errbuf));
  if(msg == NULL) {
    trace(LOG_ERR, "control: Received bad json: %s", errbuf);
    return;
  }

  const char *cmd = ntv_get_str(msg, "cmd");
  if(cmd == NULL)
    return;

  if(!strcmp(cmd, "reloadConfig")) {
    config_reload();
    return;
  } else {
    trace(LOG_ERR, "control: Got unknown command: %s", cmd);
  }
}





static void
control_input(void *aux, int opcode,
              const void *buf, size_t len)
{
  switch(opcode) {
  case 0:
    trace(LOG_NOTICE, "control: Control closed");
    disconnect();
    break;
  case WS_OPCODE_CLOSE:
    break;
  case 1:
    control_input_json(buf);
    break;
  }
}


static ws_client_t *
try_connect(const char *url)
{
  char errbuf[512];

  ws_client_t *wsc =
    ws_client_create(control_input, NULL,
                     WSC_URL(url), NULL);
  if(wsc == NULL) {
    trace(LOG_ERR, "control: Failed to connect to endpoint %s -- %s",
          url, errbuf);
    sleep(1);
  } else {
    trace(LOG_INFO, "control: Connected to %s", url);
  }
  return wsc;
}


static void *
control_thread(void *aux)
{
  static char *current_url;

  pthread_mutex_lock(&ctrl_mutex);

  while(1) {

    if(strcmp(ctrl_wanted_url ?: "", current_url ?: "")) {
      // Control URL has changed
      strset(&current_url, ctrl_wanted_url);

      if(ctrl_con != NULL) {
        ws_client_send_close(ctrl_con, WS_STATUS_GOING_AWAY, "Reconfigured");
      }
      continue;
    }

    if(ctrl_con == NULL && current_url != NULL) {
      // Try to connect
      pthread_mutex_unlock(&ctrl_mutex);

      ws_client_t *wsc = try_connect(current_url);
      pthread_mutex_lock(&ctrl_mutex);

      if(wsc != NULL) {
        ws_client_start(wsc);
        ctrl_con = wsc;
        atomic_set(&g_have_control_connection, 1);
      }
      continue;
    }

    pthread_cond_wait(&ctrl_cond, &ctrl_mutex);
  }

  pthread_mutex_unlock(&ctrl_mutex);
  return NULL;
}


static int
control_reconfigure(const ntv_t *conf)
{
  pthread_mutex_lock(&ctrl_mutex);
  strset(&ctrl_wanted_url, ntv_get_str(conf, "control"));
  pthread_cond_signal(&ctrl_cond);
  pthread_mutex_unlock(&ctrl_mutex);
  return 0;
}



CONFIG_SUB(control_reconfigure, "control", 1001);


static void
control_init(void)
{
  pthread_attr_t attr;
  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
  pthread_t tid;
  pthread_create(&tid, &attr, control_thread, NULL);
  pthread_attr_destroy(&attr);
}


INITME(control_init, NULL, 10);

