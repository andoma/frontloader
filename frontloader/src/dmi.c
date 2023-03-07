#include "dmi.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdint.h>
#include <limits.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

char *
dmi_get_string(int type, int instance, int index)
{
  char path[PATH_MAX];
  uint8_t buf[4096];
  snprintf(path, sizeof(path), "/sys/firmware/dmi/entries/%d-%d/raw",
           type, instance);
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if(fd == -1)
    return NULL;

  int len = read(fd, buf, sizeof(buf) - 1);
  close(fd);
  if(len < 1) {
    return NULL;
  }

  buf[len] = 0; // Safe null-terminate

  uint8_t fixed_len = buf[1];
  if(len < fixed_len)
    return NULL;

  if(index> fixed_len)
    return NULL;
  int si = buf[index];
  const char *sp = (const char *)buf + fixed_len;
  while(si > 1 && *sp) {
    sp += strlen(sp);
    sp++;
    si--;
  }

  if(*sp == 0)
    return NULL;

  return strdup(sp);
}
