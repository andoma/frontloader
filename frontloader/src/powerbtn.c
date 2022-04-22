#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <linux/input.h>
#include <signal.h>
#include <pthread.h>

#include "libsvc/init.h"
#include "libsvc/trace.h"


static void *
powerbtn_thread(void *aux)
{
  int fd = open("/dev/input/event0", O_RDONLY);
  if(fd == -1)
    return NULL;
  while(1) {
    struct input_event ie;
    if(read(fd, &ie, sizeof(ie)) != sizeof(ie))
      break;
    if(ie.type == EV_KEY && ie.value == 1) {
      // Key down
      if(ie.code == KEY_POWER) {
        if(!kill(1, SIGUSR2)) // Halt
          trace(LOG_ALERT, "Power button event. Power off system");
        else
          trace(LOG_ALERT,
                "Power button event. Unable to power off system -- %s",
                strerror(errno));
      } else {
        trace(LOG_INFO, "Got key down event for keycode %d", ie.code);
      }
    }
  }
  close(fd);
  return NULL;
}





static void
powerbtn_init(void)
{
  pthread_t tid;
  pthread_attr_t attr;
  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
  pthread_create(&tid, &attr, powerbtn_thread, NULL);
}


INITME(powerbtn_init, NULL, 100);
