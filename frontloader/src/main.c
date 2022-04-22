#include <sys/stat.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <zlib.h>

#include "libsvc/libsvc.h"
#include "libsvc/trace.h"
#include "libsvc/err.h"
#include "libsvc/ntv.h"
#include "libsvc/misc.h"
#include "libsvc/http_client.h"

#include "logging.h"
#include "coreupload.h"
#include "config.h"

extern int g_write_stdout;

/**
 *
 */
static void
handle_sigpipe(int x)
{
  return;
}


/**
 *
 */
int
main(int argc, char **argv)
{
  int c;
  sigset_t set;
  const char *config_url = NULL;

  signal(SIGPIPE, handle_sigpipe);

  if(strstr(argv[0], "coreupload")) {
    int r = coreupload(argc, argv);
    exit(r);
  }

  sigfillset(&set);
  sigdelset(&set, SIGQUIT);
  sigdelset(&set, SIGILL);
  sigdelset(&set, SIGTRAP);
  sigdelset(&set, SIGABRT);
  sigdelset(&set, SIGFPE);
  sigdelset(&set, SIGBUS);
  sigdelset(&set, SIGSEGV);
  sigdelset(&set, SIGSYS);
  sigprocmask(SIG_BLOCK, &set, NULL);

  while((c = getopt(argc, argv, "s:c:lo")) != -1) {
    switch(c) {
    case 's':
      enable_syslog(PROGNAME, optarg);
      break;
    case 'c':
      config_url = optarg;
      break;
    case 'l':
      logging_early_init();
      break;
    case 'o':
      g_write_stdout = 1;
      break;
    }
  }


  srand48(getpid() ^ time(NULL));

  libsvc_init();

  trace(LOG_NOTICE,
        "Running pid %d uid %d euid %d gid %d",
        getpid(), getuid(), geteuid(), getgid());

  config_init(config_url);

  config_reload();

  config_start_autoreloader();

  // Mask out some signals handled by runner.c
  sigdelset(&set, SIGCHLD);
  sigdelset(&set, SIGUSR1);

  while(1) {
    int delivered = 0;
    if(!sigwait(&set, &delivered)) {
      trace(LOG_DEBUG, "Main loop got signal %d", delivered);
      if(delivered == SIGTERM || delivered == SIGINT)
        break;
      if(delivered == SIGHUP) {
        config_reload();
      }
    }
  }

  config_inhibit_updates();

  trace(LOG_NOTICE, "Stopping");

  libsvc_fini();

  return 0;
}
