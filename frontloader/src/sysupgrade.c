#include <limits.h>
#include <pthread.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>

#include "libsvc/http_client.h"
#include "libsvc/trace.h"
#include "libsvc/ntv.h"
#include "libsvc/err.h"
#include "libsvc/misc.h"


#include <linux/kexec.h>
#include <sys/reboot.h>
#include <sys/utsname.h>
#include <syscall.h>

#include "config.h"
#include "docker_image.h"


static int do_reboot_kexec;
static char *current_system_commit;

static int
sysupgrade_load_manifest(const ntv_t *kernel_conf)
{
  const char *manifest_url = ntv_get_str(kernel_conf, "manifest");
  if(manifest_url == NULL)
    return 0;

  const ntv_t *docker_config = ntv_get_map(kernel_conf, "docker");

  const char *cmdline = ntv_get_str(kernel_conf, "cmdline");
  scoped_err_t *err = NULL;
  scoped_ntv_t *manifest = docker_image_load_manifest(manifest_url, &err,
                                                      docker_config);

  if(manifest == NULL) {
    scoped_char *errstr = err_str(err);
    trace(LOG_ERR, "Failed to load manifest from %s -- %s",
          manifest_url, errstr);
    return -1;
  }

  scoped_ntv_t *config = docker_image_get_config(manifest, &err,
                                                 docker_config);
  if(config == NULL) {
    scoped_char *errstr = err_str(err);
    trace(LOG_ERR, "Failed to get docker image config -- %s",
          errstr);
    return -1;
  }

  const ntv_t *config_inner = ntv_get_map(config, "config");
  const char *commit =
    ntv_get_str(ntv_field_from_path(config_inner, (const char *[]){"Labels", "commit", NULL}), NULL);
  if(commit == NULL)
    return -1;

  if(!strcmp(commit, current_system_commit)) {
    // Already running this image
    return 0;
  }

  trace(LOG_INFO, "System need upgrade to %s, loading kernel", commit);

  char template[] = "/tmp/frontloader.sysupgrade.XXXXXX";
  char *dirname = mkdtemp(template);
  if(dirname == NULL) {
    trace(LOG_ERR, "sysupgrade: Failed to create temporary directory %s -- %s",
          template, strerror(errno));
    return -1;
  }

  if(docker_image_install(template, manifest, &err, docker_config)) {
    scoped_char *errstr = err_str(err);
    trace(LOG_ERR, "sysupgrade: Failed to install docker image %s -- %s",
          manifest_url, errstr);
    rm_rf(template, 1);
    return -1;
  }

  char kpath[PATH_MAX];
  snprintf(kpath, sizeof(kpath), "%s/bzImage", template);

  int fd = open(kpath, O_RDONLY);
  if(fd == -1) {
    trace(LOG_ERR, "sysupgrade: Docker image %s unable to open /bzImage -- %s",
          manifest_url, strerror(errno));
    rm_rf(template, 1);
    return -1;
  }

  char oldcmdline[8192];
  if(cmdline == NULL) {
    int cfd = open("/proc/cmdline", O_RDONLY);
    if(cfd == -1) {
    badcmdline:
      trace(LOG_ERR, "sysupgrade: Docker image %s unable to read current cmdline "
            "from /proc/cmdline -- %s",
            manifest_url, strerror(errno));
      rm_rf(template, 1);
      close(fd);
      return -1;
    }
    int olen = read(cfd, oldcmdline, sizeof(oldcmdline) - 1);
    int errnosave = errno;
    close(cfd);
    errno = errnosave;
    if(olen < 0) {
      goto badcmdline;
    }
    oldcmdline[olen] = 0;
    char *lf = strchr(oldcmdline, 0xa);
    if(lf != NULL)
      *lf = 0;
    cmdline = oldcmdline;
  }


  int r = syscall(SYS_kexec_file_load,
                  (int)fd,
                  (int)-1,
                  (long)(strlen(cmdline) + 1),
                  cmdline,
                  (long)(KEXEC_FILE_NO_INITRAMFS | KEXEC_ARCH_DEFAULT));
  if(r) {
    trace(LOG_ERR, "kexec: Unable to load kernel from %s -- %s",
          manifest_url, strerror(errno));
    close(fd);
    rm_rf(template, 1);
    return -1;
  }
  close(fd);
  rm_rf(template, 1);

  do_reboot_kexec = 1;

  trace(LOG_INFO, "System need upgrade to %s, kernel loaded and ready to go, "
        "cmdline='%s', shutting down system", commit, cmdline);
  kill(getpid(), SIGTERM);
  return 1;
}

static pthread_mutex_t sysupgrade_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t sysupgrade_cond = PTHREAD_COND_INITIALIZER;

static ntv_t *pending_kernel_conf;
static pthread_t sysupgrade_tid;

static void *
sysupgrade_thread(void *aux)
{
  ntv_t *kernel_conf = NULL;

  pthread_mutex_lock(&sysupgrade_mutex);

  while(1) {

    if(!ntv_cmp(kernel_conf, pending_kernel_conf)) {
      pthread_cond_wait(&sysupgrade_cond, &sysupgrade_mutex);
      continue;
    }

    ntv_release(kernel_conf);
    kernel_conf = ntv_copy(pending_kernel_conf);

    if(kernel_conf == NULL)
      continue;

    pthread_mutex_unlock(&sysupgrade_mutex);

    int r = sysupgrade_load_manifest(kernel_conf);
    if(r < 0) {
      sleep(60);
      // Failure, release current config to force retry from pending
      ntv_release(kernel_conf);
      kernel_conf = NULL;
    }

    pthread_mutex_lock(&sysupgrade_mutex);
  }
  return NULL;
}


static int
sysupgrade_reconfigure(const ntv_t *conf)
{
  const ntv_t *kernel_conf = ntv_get_map(conf, "kernel");

  pthread_mutex_lock(&sysupgrade_mutex);
  ntv_release(pending_kernel_conf);
  pending_kernel_conf = ntv_copy(kernel_conf);

  if(kernel_conf != NULL) {

    if(sysupgrade_tid == 0) {
      // First time we're getting a sysupgrade manifest
      // We load it synchronously to avoid booting any containers, etc
      int r = sysupgrade_load_manifest(kernel_conf);
      if(r == 1) {
        // New kernel needs to be booted
        // return !0 to avoid any further config changes
        pthread_mutex_unlock(&sysupgrade_mutex);
        return 1;
      }
    }
  }
  pthread_cond_broadcast(&sysupgrade_cond);

  if(sysupgrade_tid == 0) {
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_create(&sysupgrade_tid, &attr, sysupgrade_thread, NULL);
    pthread_attr_destroy(&attr);
  }

  pthread_mutex_unlock(&sysupgrade_mutex);
  return 0;
}


static void
sysupgrade_init(void)
{
  struct utsname un;
  if(uname(&un)) {
    trace(LOG_ERR, "Failed to check current kernel release -- %s",
          strerror(errno));
    return;
  }

  if(getenv("FL_NO_SYSUPGADE")) {
    trace(LOG_INFO, "System upgrade disabled by environment variables");
    return;
  }

  char *flprefix = strstr(un.release, "-fl-");
  if(flprefix == NULL) {
    trace(LOG_DEBUG, "Not a frontloader kernel, system upgrades disabled");
    return;
  }

  current_system_commit = strdup(flprefix + strlen("-fl-"));
  current_system_commit[strspn(current_system_commit, "0123456789abcdef")] = 0;

  trace(LOG_DEBUG, "Running frontloader kernel git commit:%s, system upgrades enabled",
        current_system_commit);

  config_registration_t cr = {
    .cb = sysupgrade_reconfigure,
    .name = "sysupgrade",
    .prio = 500
  };
  config_register_update(cr);
}

static void
sysupgrade_fini(void)
{
  if(do_reboot_kexec) {
    reboot(RB_KEXEC);
    // Failed to reboot? Ask init to do it for us
    kill(1, SIGTERM);
  }
}

INITME(sysupgrade_init, sysupgrade_fini, 1);
