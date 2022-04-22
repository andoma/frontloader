#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#include "libsvc/ntv.h"
#include "libsvc/misc.h"
#include "libsvc/trace.h"

#include "config.h"


static int
sysctl_reconfigure(const ntv_t *conf)
{
  const ntv_t *sysparams = ntv_get_map(conf, "sysparams");

  if(sysparams == NULL)
    return 0;

  NTV_FOREACH_TYPE(s, sysparams, NTV_STRING) {

    scoped_char *path = fmt("/proc/sys/%s", s->ntv_name);

    int fd = open(path, O_CLOEXEC | O_RDWR);
    if(fd == -1) {
      trace(LOG_WARNING, "Unable to open %s for writing -- %s",
            path, strerror(errno));
      continue;
    }

    const char *value = s->ntv_string;
    size_t valuelen = strlen(value);

    if(write(fd, value, valuelen) != valuelen) {
      trace(LOG_WARNING, "Unable to write '%s' to %s",
            value, path);
    }
    close(fd);

    trace(LOG_DEBUG, "%s = %s", path, value);
  }

  return 0;
}


CONFIG_SUB(sysctl_reconfigure, "sysctl", 100);

