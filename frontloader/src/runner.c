#define _GNU_SOURCE
#include <assert.h>
#include <glob.h>
#include <sched.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <signal.h>
#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <limits.h>
#include <sys/sysmacros.h>
#include <sys/sendfile.h>
#include <sys/syscall.h>
#include <sys/file.h>
#include <sys/resource.h>

#include <linux/capability.h>
#include <linux/securebits.h>

#include <grp.h>

#include "libsvc/init.h"
#include "libsvc/ntv.h"
#include "libsvc/trace.h"
#include "libsvc/misc.h"
#include "libsvc/err.h"
#include "libsvc/strvec.h"
#include "libsvc/intvec.h"
#include "libsvc/mbuf.h"
#include "libsvc/strtab.h"

#include "config.h"
#include "docker_image.h"

int g_write_stdout;

static int check_interval = 600;

static pthread_mutex_t container_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t container_allpids_cond = PTHREAD_COND_INITIALIZER;
static intvec_t allpids;

static LIST_HEAD(, container) containers;

typedef struct container {
  LIST_ENTRY(container) c_link;
  char *c_id;
  ntv_t *c_config;
  ntv_t *c_manifest;
  pid_t c_pid;
  int c_exit_status;
  int c_force_restart;
  pthread_cond_t c_cond;
  int c_mark;
  int c_want_running;
  int c_auto_debug_exec;
  int c_will_start;
} container_t;



typedef struct {
  char **env;
  const char *cmd;
  const char *root_path;
  const char *title;
  strvec_t bindmounts;

  int ctrl_pipe[2];
  int stdout_pipe[2];

  int flags;
  uid_t uid;
  gid_t gid;


#define RA_ROOTFS_READONLY 0x1

  const char *hostname;

  const ntv_t *files;

  struct __user_cap_header_struct cap_header;
  struct __user_cap_data_struct cap_data[3];

  // Very simple (but useful) cron machinery
  const ntv_t *cron;
  time_t cron_next_event;

  int fdlimits;

} run_args_t;




static void
enable_cap(run_args_t *ra, int cap)
{
  if(cap_valid(cap)) {
    ra->cap_data[CAP_TO_INDEX(cap)].inheritable |= CAP_TO_MASK(cap);
  }
}



struct strtab captable[] = {
  { "CHOWN", CAP_CHOWN },
  { "DAC_OVERRIDE", CAP_DAC_OVERRIDE },
  { "DAC_READ_SEARCH", CAP_DAC_READ_SEARCH },
  { "FOWNER", CAP_FOWNER },
  { "FSETID", CAP_FSETID },
  { "KILL", CAP_KILL },
  { "SETGID", CAP_SETGID },
  { "SETUID", CAP_SETUID },
  { "SETPCAP", CAP_SETPCAP },
  { "LINUX_IMMUTABLE", CAP_LINUX_IMMUTABLE },
  { "NET_BIND_SERVICE", CAP_NET_BIND_SERVICE },
  { "NET_BROADCAST", CAP_NET_BROADCAST },
  { "NET_ADMIN", CAP_NET_ADMIN },
  { "NET_RAW", CAP_NET_RAW },
  { "IPC_LOCK", CAP_IPC_LOCK },
  { "IPC_OWNER", CAP_IPC_OWNER },
  { "SYS_MODULE", CAP_SYS_MODULE },
  { "SYS_RAWIO", CAP_SYS_RAWIO },
  { "SYS_CHROOT", CAP_SYS_CHROOT },
  { "SYS_PTRACE", CAP_SYS_PTRACE },
  { "SYS_PACCT", CAP_SYS_PACCT },
  { "SYS_ADMIN", CAP_SYS_ADMIN },
  { "SYS_BOOT", CAP_SYS_BOOT },
  { "SYS_NICE", CAP_SYS_NICE },
  { "SYS_RESOURCE", CAP_SYS_RESOURCE },
  { "SYS_TIME", CAP_SYS_TIME },
  { "SYS_TTY_CONFIG", CAP_SYS_TTY_CONFIG },
  { "MKNOD", CAP_MKNOD },
  { "LEASE", CAP_LEASE },
  { "AUDIT_WRITE", CAP_AUDIT_WRITE },
  { "AUDIT_CONTROL", CAP_AUDIT_CONTROL },
  { "SETFCAP", CAP_SETFCAP },
  { "MAC_OVERRIDE", CAP_MAC_OVERRIDE },
  { "MAC_ADMIN", CAP_MAC_ADMIN },
  { "SYSLOG", CAP_SYSLOG },
  { "WAKE_ALARM", CAP_WAKE_ALARM },
  { "BLOCK_SUSPEND", CAP_BLOCK_SUSPEND },
  { "AUDIT_READ", CAP_AUDIT_READ }
};

static int
enable_cap_str(run_args_t *ra, const char *str)
{
  const int cap = str2val(str, captable);
  if(cap == -1)
    return -1;
  enable_cap(ra, cap);
  return 0;
}







static int
container_error(const run_args_t *ra, const char *fmt, ...)
{
  if(ra->ctrl_pipe[1] != -1) {
    va_list ap;
    va_start(ap, fmt);
    vdprintf(ra->ctrl_pipe[1], fmt, ap);
    va_end(ap);
  }
  return 129;
}


static int
write_file(run_args_t *ra, const char *path,
           const void *data, size_t size,
           int uid, int gid, int mode)
{
  if(*path != '/')
    return 0;

  char *dirname = mystrdupa(path);
  char *basename = strrchr(dirname, '/');
  if(basename == NULL || basename[1] == 0)
    return -1;

  if(basename != dirname) {
    *basename = 0;
    if(mkdir_p(dirname, 0755)) {
      return container_error(ra, "Unable to write %s, Unable to mkdir %s -- %s",
                             path, dirname, strerror(errno));
    }
  }

  int fd = open(path, O_CLOEXEC | O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if(fd == -1) {
    return container_error(ra, "Unable to open %s for writing -- %s",
                           path, strerror(errno));
  }

  if(fchown(fd, uid, gid) < 0) {
    const int saved_errno = errno;
    close(fd);
    return container_error(ra, "Unable to chown %s to uid:%d gid:%d -- %s",
                           path, uid, gid, strerror(saved_errno));
  }
  if(fchmod(fd, mode) < 0) {
    const int saved_errno = errno;
    close(fd);
    return container_error(ra, "Unable to chmod %s to 0%o -- %s",
                           path, mode, strerror(saved_errno));
  }

  if(write(fd, data, size) != size) {
    close(fd);
    return container_error(ra, "Unable to write to %s", path);
  }
  close(fd);
  return 0;
}




static int
write_files(run_args_t *ra, const ntv_t *files)
{
  int r;
  const char *contents;
  NTV_FOREACH(f, files) {
    if(f->ntv_name == NULL)
      continue;
    switch(f->ntv_type) {
    case NTV_STRING:
      r = write_file(ra, f->ntv_name, f->ntv_string, strlen(f->ntv_string), 0, 0, 0644);
      break;
    case NTV_MAP:
      contents = ntv_get_str(f, "contents");
      if(contents == NULL)
        continue;
      r = write_file(ra, f->ntv_name, contents, strlen(contents),
                     ntv_get_int(f, "uid", 0), ntv_get_int(f, "gid", 0),
                     ntv_get_int(f, "mode", 0644));
      break;
    default:
      r = 0;
      break;
    }
    if(r)
      return r;
  }
  return 0;
}



static int
container_exec(const run_args_t *ra, const char *cmd)
{
  setsid();
  int devnull = open("/dev/null", O_RDWR);
  if(devnull < 0) {
    return container_error(ra, "Unable to open /dev/null -- %s",
                           strerror(errno));
  }
  dup2(devnull, 0);

  if(ra->stdout_pipe[1] >= 0) {
    dup2(ra->stdout_pipe[1], 1);
    dup2(ra->stdout_pipe[1], 2);

    if(devnull > 0)
      close(devnull);
  } else {
    dup2(devnull, 1);
    dup2(devnull, 2);
    if(devnull > 2)
      close(devnull);
  }

  const char *shell;

  if(!access("/bin/bash", X_OK))
    shell = "/bin/bash";
  else
    shell = "/bin/sh";

  if(ra->gid) {
    const gid_t gid = ra->gid;
    if(setgroups(1, &(gid_t) { gid })) {
      return container_error(ra, "Unable to setgroups({%u}) -- %s",
                             gid, strerror(errno));
    }

    if(setresgid(gid, gid, gid)) {
      return container_error(ra, "Unable to setresgid(%u) -- %s",
                             gid, strerror(errno));
    }
  }


  if(ra->uid) {

    prctl(PR_SET_KEEPCAPS, 1L);

    if(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
      return container_error(ra, "Unable to set NO_NEW_PRIVS -- %s",
                             strerror(errno));
    }

    const uid_t uid = ra->uid;
    if(setresuid(uid, uid, uid)) {
      return container_error(ra, "Unable to setresuid(%u) -- %s",
                             uid, strerror(errno));
    }

    struct __user_cap_header_struct cap_header = ra->cap_header;

    cap_header.pid = syscall(SYS_gettid);
    if(syscall(SYS_capset, &cap_header, ra->cap_data)) {
      return container_error(ra, "Unable to set capabilites -- %s",
                             strerror(errno));
    }

    for(int cap = 0; cap_valid(cap); cap++) {
      if(ra->cap_data[CAP_TO_INDEX(cap)].inheritable & CAP_TO_MASK(cap)) {
        if(prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, cap, 0, 0)) {
          return container_error(ra, "Unable to raise ambience for cap %d-- %s",
                                 cap, strerror(errno));
        }
      }
    }


    if(prctl(PR_SET_SECUREBITS,
             SECBIT_NO_SETUID_FIXUP |
             SECBIT_NO_SETUID_FIXUP_LOCKED |
             SECBIT_NOROOT |
             SECBIT_NOROOT_LOCKED |
             SECBIT_NO_CAP_AMBIENT_RAISE |
             SECBIT_NO_CAP_AMBIENT_RAISE_LOCKED)) {
      return container_error(ra, "Unable to turn on secure bits -- %s",
                             strerror(errno));
    }

  }

  const char *argv[4] = {shell, "-c", cmd, NULL };
  execve(shell, (char **)argv, ra->env);
  return container_error(ra, "Unable to exec '%s -c %s' -- %s",
                         shell, cmd, strerror(errno));
}

static int container_terminated;
static int container_alarm;

static void
container_init_term(int x)
{
  container_terminated = 1;
}

static void
container_init_alarm(int x)
{
  container_alarm = 1;
}


static void
cron_check(run_args_t *ra)
{
  time_t now = time(NULL);
  if(now < ra->cron_next_event)
    return;

  const char *cmd = ntv_get_str(ra->cron, "command");
  if(cmd == NULL)
    return;

  const int hour = ntv_get_int(ra->cron, "hour", -1);
  const int minute = ntv_get_int(ra->cron, "minute", -1);

  if(ra->cron_next_event) {
    const char *lockfile = ntv_get_str(ra->cron, "lockfile");
    if(lockfile != NULL) {

      pid_t p1 = fork();
      if(p1 == 0) {

        int lockfd = lockfile ? open(lockfile, O_CLOEXEC | O_CREAT | O_RDWR, 0644) : -1;
        if(lockfd != -1) {
          flock(lockfd, LOCK_EX);
          pid_t p2 = fork();
          if(p2 == 0) {
            exit(container_exec(ra, cmd));
          }
          int status;
          waitpid(p2, &status, 0);
          close(lockfd);
          exit(0);
        }
      }

    } else {
      pid_t p = fork();
      if(p == 0) {
        exit(container_exec(ra, cmd));
      }
    }
  }

  struct tm tm;
  gmtime_r(&now, &tm);
  tm.tm_sec = 0;

  if(minute != -1)
    tm.tm_min = minute;

  if(hour != -1)
    tm.tm_hour = hour;

  time_t next = mktime(&tm);
  while(next <= now) {

    if(hour != -1)
      tm.tm_mday++;
    else if(minute != -1)
      tm.tm_hour++;
    else
      tm.tm_min++;

    next = mktime(&tm);
  }

  ra->cron_next_event = next;
  int seconds = next - now;

  if(seconds < 1)
    seconds = 1;
  if(seconds > 86400) // Weird, play it safe
    seconds = 86400;
  alarm(seconds);
}


static int
container_init_proc(run_args_t *ra, pid_t primary_pid)
{
  // This is init(1) in the new namespace
  struct sigaction sa = {};
  sa.sa_handler = container_init_term;
  sigaction(SIGTERM, &sa, NULL);

  sa.sa_handler = container_init_alarm;
  sigaction(SIGALRM, &sa, NULL);

  char buf[64];
  snprintf(buf, sizeof(buf), "init-%s", ra->title);
  prctl(PR_SET_NAME, buf, 0, 0, 0);

  close(ra->ctrl_pipe[1]);
  ra->ctrl_pipe[1] = -1;

  int status = 0;
  while(1) {

    cron_check(ra);
    pid_t p = waitpid(-1, &status, 0);
    if(p == primary_pid || container_terminated)
      break;

    if(container_alarm) {
      container_alarm = 0;
    }

    // Some kind of error happened (EINTR is when we get a signal)
    if(p == -1 && errno != EINTR)
      break;
  }

  // Ask any remaining processes in this PID space to terminate
  kill(-1, SIGTERM);

  alarm(60); // One minute until we SIGKILL everything
  container_alarm = 0;

  // Catch all remaining processes
  while(1) {
    pid_t p = waitpid(-1, NULL, 0);
    if(container_alarm) {
      // Ok, so something is stuck, kill everything
      kill(-1, SIGKILL);
      continue;
    }
    if(p <= 0) {
      break;
    }
  }

  if(ra->stdout_pipe[1] >= 0)
    close(ra->stdout_pipe[1]);

  if(WIFEXITED(status)) {
    return WEXITSTATUS(status);
  }
  return 100;
}


static int
container_trampoline(run_args_t *ra)
{
  // If parent terminate we want to terminate as well
  if(prctl(PR_SET_PDEATHSIG, SIGTERM)) {
    return container_error(ra, "Unable to set PDEATHSIG -- %s", strerror(errno));
  }

  if(ra->hostname != NULL) {
    if(sethostname(ra->hostname, strlen(ra->hostname)) < 0) {
      return container_error(ra, "Unable to set hostname -- %s", strerror(errno));
    }
  }


  if(ra->fdlimits) {
    struct rlimit lim;
    if(getrlimit(RLIMIT_NOFILE, &lim) == -1)
      return container_error(ra, "Unable to get current fdlimit -- %s", strerror(errno));

    lim.rlim_cur = ra->fdlimits;
    lim.rlim_max = ra->fdlimits;
    if(setrlimit(RLIMIT_NOFILE, &lim) == -1)
      return container_error(ra, "Unable to set  fdlimit to %d -- %s",
                             ra->fdlimits, strerror(errno));
  }

  if(mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL)) {
    return container_error(ra, "Unable to do a private remount of / -- %s",
                           strerror(errno));
  }

  if(chdir(ra->root_path)) {
    return container_error(ra, "Unable chdir to %s -- %s",
                           ra->root_path, strerror(errno));
  }

  for(int i = 0; i + 1 < ra->bindmounts.count; i+=2) {
    const char *src_path = strvec_get(&ra->bindmounts, i);
    const char *dst_path = strvec_get(&ra->bindmounts, i + 1);
    int fd;

    if(!strcmp(src_path, "proc") || !strcmp(src_path, "sysfs")) {
      continue;
    }

    if(*dst_path != '/')
      continue;
    dst_path++;

    struct stat st;
    if(lstat(src_path, &st) < 0)
      continue;

    switch(st.st_mode & S_IFMT) {
    default:
      continue;
    case S_IFDIR:
      mkdir(dst_path, st.st_mode & 0777);
      break;
    case S_IFBLK:
    case S_IFCHR:
    case S_IFIFO:
    case S_IFREG:
    case S_IFSOCK:
      fd = open(dst_path,  O_NOFOLLOW | O_CREAT | O_RDWR, st.st_mode & 0777);
      if(fd < 0)
        continue;
      close(fd);
      break;
    }

    if(mount(src_path, dst_path, "bind", MS_BIND | MS_PRIVATE, "")) {
      return container_error(ra, "Unable to bind mount inner:%s to outside:%s -- %s",
                             dst_path, src_path, strerror(errno));
    }
  }

  if(mount(".", "/", NULL, MS_MOVE, NULL)) {
    return container_error(ra, "Unable move root mount -- %s",
                           strerror(errno));
  }

  if(chroot(".") < 0) {
    return container_error(ra, "Unable to chroot -- %s",
                           ra->root_path, strerror(errno));
  }

  if(chdir("/") < 0) {
    return container_error(ra, "Unable to chdir to / -- %s",
                           strerror(errno));
  }


  if(mount("proc", "/proc", "proc", 0, "")) {
    return container_error(ra, "Unable to mount /proc -- %s",
                           strerror(errno));
  }

  if(mount("sysfs", "/sys", "sysfs", 0, "")) {
    return container_error(ra, "Unable to mount /sys -- %s",
                           strerror(errno));
  }

  if(ra->files) {
    int r = write_files(ra, ra->files);
    if(r)
      return r;
  }

  if(ra->flags & RA_ROOTFS_READONLY) {
    if(mount(NULL, "/", NULL, MS_REMOUNT | MS_RDONLY, "") < 0) {
      return container_error(ra, "Unable to remount rootfs to read-only -- %s",
                             strerror(errno));
    }
  }

  if(getpid() == 1) {
    // We run in a new pid namespace

    pid_t primary_pid = fork();
    if(primary_pid == -1) {
      return container_error(ra, "Unable to fork -- %s", strerror(errno));
    }

    if(primary_pid != 0) {
      // We are init(1)
      exit(container_init_proc(ra, primary_pid));
    }
  }

  return container_exec(ra, ra->cmd);

}


static int
container_child(void *aux)
{
  /**
   * RED ALERT!
   *
   * Nothing in here (including container_trampoline()) may use *any*
   * type of memoy mallocation until we've exec()ed.  The reason for
   * this is that clone() which is used to spawn this child doesn't
   * invoke the necessary fork-handlers. These handlers are used to
   * clean up any locked mutexes which might be held by *another*
   * thread in the parent process at the time of clone(). If this
   * happens we will hang forever.
   */

  run_args_t *ra  = aux;

  sigset_t set;
  sigfillset(&set);
  sigprocmask(SIG_UNBLOCK, &set, NULL);

  if(ra->stdout_pipe[0] >= 0)
    close(ra->stdout_pipe[0]);
  close(ra->ctrl_pipe[0]);

  int r = container_trampoline(ra);

  if(ra->stdout_pipe[1] >= 0)
    close(ra->stdout_pipe[1]);
  close(ra->ctrl_pipe[1]);
  _exit(r);
}


static int
copyfile(const char *src_path, const char *dst_path)
{
  int src_fd = open(src_path, O_RDONLY | O_CLOEXEC);
  if(src_fd == -1)
    return -1;

  int dst_fd = open(dst_path, O_TRUNC | O_CREAT | O_WRONLY | O_CLOEXEC, 0664);
  if(dst_fd == -1) {
    close(src_fd);
    return -1;
  }

  while(1) {

    int r = sendfile(dst_fd, src_fd, NULL, 65536 * 256);
    if(r == -1) {
      close(dst_fd);
      close(src_fd);
      return -1;
    }

    if(r == 0)
      break;
  }
  close(dst_fd);
  close(src_fd);
  return 0;
}


static int
install_etc(const char *basepath, const char *hostname,
            const char *title)
{
  scoped_char *resolv_conf_path = fmt("%s/etc/resolv.conf", basepath);

  if(copyfile("/etc/resolv.conf", resolv_conf_path)) {
    trace(LOG_ERR, "[%s]: Failed to install /etc/hosts", title);
    return -1;
  }

  scoped_char *hosts_path = fmt("%s/etc/hosts", basepath);
  const char *hosts_conf = "127.0.0.1 localhost\n";
  if(writefile(hosts_path, hosts_conf, strlen(hosts_conf), 0))
    return -1;

  scoped_char *hostname_path = fmt("%s/etc/hostname", basepath);
  scoped_char *hostname_conf = fmt("%s\n", hostname);
  if(writefile(hostname_path, hostname_conf, strlen(hostname_conf), 0))
    return -1;

  return 0;
}


typedef struct {
  int fd;
  char *name;
  pid_t pid;
} redirect_t;

static const char months[12][4] = {
  "Jan", "Feb", "Mar", "Apr", "May", "Jun",
  "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
};

static void *
redirect_thread(void *aux)
{
  redirect_t *redir = aux;
  int len;
  scoped_mbuf_t linebuf = MBUF_INITIALIZER(linebuf);

  int syslog_socket = socket(AF_LOCAL, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if(syslog_socket != -1) {
    struct sockaddr_un syslog_dst;
    syslog_dst.sun_family = AF_LOCAL;
    strcpy(syslog_dst.sun_path, "/dev/log");

    if(connect(syslog_socket, (struct sockaddr *)&syslog_dst,
               sizeof(syslog_dst))) {
      close(syslog_socket);
      syslog_socket = -1;
    }
  }

  trace(LOG_INFO, "[%s]: Capture stdout/stderr to %s%s", redir->name,
        g_write_stdout ? "stdout " : "",
        syslog_socket != -1 ? "syslog " : "");

  while(1) {
    uint8_t readbuf[4096];

    int r = read(redir->fd, readbuf, sizeof(readbuf));
    if(r <= 0)
      break;
    mbuf_append(&linebuf, readbuf, r);
    while((len = mbuf_find(&linebuf, '\n')) != -1) {
      char *line = malloc(len + 1);
      mbuf_read(&linebuf, line, len);
      line[len] = 0;
      mbuf_drop(&linebuf, 1); // drop \n

      struct timeval tv;
      gettimeofday(&tv, NULL);
      struct tm tm;
      localtime_r(&tv.tv_sec, &tm);

      if(syslog_socket != -1) {
        scoped_char *syslog_line = fmt("<%d>%s %d %02d:%02d:%02d %s[%d]: %s",
                                       LOG_INFO | LOG_LOCAL2,
                                       months[tm.tm_mon], tm.tm_mday,
                                       tm.tm_hour, tm.tm_min, tm.tm_sec,
                                       redir->name, redir->pid, line);

        send(syslog_socket, syslog_line, strlen(syslog_line), MSG_NOSIGNAL);
      }

      if(g_write_stdout) {
        printf("%s[%d] %s\n", redir->name, redir->pid, line);
      }
      free(line);
    }
  }

  if(syslog_socket != -1)
    close(syslog_socket);

  close(redir->fd);
  free(redir->name);
  free(redir);
  return NULL;
}





static pid_t
launch(const char *basepath, const ntv_t *config, const char *title,
       const char *git_id, const ntv_t *docker_env, int debug_exec)
{
  scoped_ntv_t *envmap = ntv_create_map();

  ntv_set_str(envmap, "TMPDIR", "/tmp");
  ntv_set_str(envmap, "PATH", "/usr/sbin:/usr/bin:/sbin:/bin");
  ntv_set_str(envmap, "TZ", "UTC0");
  ntv_set_str(envmap, "LANG", "C");
  ntv_set_str(envmap, "SHELL", "/bin/bash");
  ntv_set_str(envmap, "HOME", "/");

  ntv_merge(envmap, docker_env);

  const ntv_t *configured_env = ntv_get_map(config, "environment");
  if(configured_env != NULL) {
    NTV_FOREACH(f, configured_env) {
      if(f->ntv_name == NULL)
        continue;
      switch(f->ntv_type) {
      default:
        break;
      case NTV_MAP:
      case NTV_LIST:
        {
          scoped_char *payload = ntv_json_serialize_to_str(f, 0);
          ntv_set_str(envmap, f->ntv_name, payload);
        }
        break;
      case NTV_STRING:
        ntv_set_str(envmap, f->ntv_name, f->ntv_string);
        break;
      }
    }
  }

  scoped_strvec(env);
  NTV_FOREACH_TYPE(f, envmap, NTV_STRING)
    strvec_pushf(&env, "%s=%s", f->ntv_name, f->ntv_string);


  if(ntv_get_int(config, "log_environment", 0)) {
    for(int i = 0; i < env.count; i++) {
      trace(LOG_INFO, "[%s]: Env: %s", title, strvec_get(&env, i));
    }
  }
  strvec_push(&env, NULL); // env must end with NULL, strvec can do this for us

  const char *cmd = ntv_get_str(config, "command");
  if(cmd == NULL) {
    trace(LOG_ERR, "[%s]: No command specified in container section", title);
    return 0;
  }

  scoped_char *debug_cmd = NULL;

  if(debug_exec) {
    trace(LOG_NOTICE, "[%s]: Previously failed to execute binary. Enabling extra ld.so debug", title);
    debug_cmd = fmt("LD_DEBUG=files %s", cmd);
    cmd = debug_cmd;
  }
  char hostname[512];

  if(gethostname(hostname, sizeof(hostname)) < 0) {
    trace(LOG_ERR, "[%s]: Unable to get hostname", title);
    return 0;
  }

  scoped_char *computed_hostname =
    git_id ? fmt("%s.%s", hostname, git_id) : NULL;

  const char *inner_hostname =
    ntv_get_str(config, "hostname") ?: computed_hostname;

  if(install_etc(basepath, inner_hostname, title))
    return 0;

  run_args_t ra = {
    .cmd = cmd,
    .cron = ntv_get_map(config, "cron"),
    .env = env.v,
    .root_path = basepath,
    .hostname = inner_hostname,
    .files = ntv_get_map(config, "files"),
    .title = title,
  };

  if(pipe2(ra.ctrl_pipe, O_CLOEXEC)) {
    trace(LOG_ERR, "[%s]: Unable to create pipe -- %s", title, strerror(errno));
    return 0;
  }
  ra.stdout_pipe[0] = -1;
  ra.stdout_pipe[1] = -1;

  const char *syslog_name = ntv_get_str(config, "id") ?: "child";

  if(ntv_get_int(config, "capture_stdio", 0)) {
    if(pipe2(ra.stdout_pipe, O_CLOEXEC)) {
      close(ra.ctrl_pipe[0]);
      close(ra.ctrl_pipe[1]);
      trace(LOG_ERR, "[%s]: Unable to create stdio output pipe", title);
      return 0;
    }
  }

  const ntv_t *bind_mounts = ntv_get_map(config, "mounts");
  if(bind_mounts != NULL) {
    NTV_FOREACH_TYPE(f, bind_mounts, NTV_STRING) {
      if(f->ntv_name != NULL) {
        char rp[PATH_MAX];

        if(!strcmp(f->ntv_string, "proc") ||
           !strcmp(f->ntv_string, "sysfs")) {
          // Legacy, we just skip these
          continue;
        }

        if(strchr(f->ntv_string, '*')) {
          glob_t gl;
          if(glob(f->ntv_string, 0, NULL, &gl)) {
            trace(LOG_ERR, "[%s]: Unable mount inside:%s to outside:%s -- %s",
                  title, f->ntv_name, f->ntv_string, strerror(errno));
            return 0;
          }

          for(int i = 0; i < gl.gl_pathc; i++) {
            if(realpath(gl.gl_pathv[i], rp) == NULL) {
              continue;
            }
            char *basename = strrchr(rp, '/');
            if(basename == NULL || strlen(basename) == 1)
              continue;
            basename++;
            scoped_char *dstname = fmt("%s/%s", f->ntv_name, basename);

            strvec_push(&ra.bindmounts, rp);
            strvec_push(&ra.bindmounts, dstname);
            trace(LOG_INFO, "[%s]: Mounted inside:%s to outside:%s",
                  title, dstname, rp);
          }
          globfree(&gl);
          continue;
        }

        if(realpath(f->ntv_string, rp) == NULL) {
          trace(LOG_ERR, "[%s]: Unable mount inside:%s to outside:%s -- %s",
                title, f->ntv_name, f->ntv_string, strerror(errno));
          return 0;
        }

        strvec_push(&ra.bindmounts, rp);
        strvec_push(&ra.bindmounts, f->ntv_name);
        trace(LOG_INFO, "[%s]: Mounted inside:%s to outside:%s",
              title, f->ntv_name, rp);
      }
    }
  }

  const ntv_t *limits = ntv_get_map(config, "limits");
  ra.fdlimits = ntv_get_int(limits, "filedescriptors", 0);

  if(ntv_get_int(config, "rootfs_read_only", 0))
    ra.flags |= RA_ROOTFS_READONLY;

  ra.uid = ntv_get_int(config, "uid", 0);
  ra.gid = ntv_get_int(config, "gid", 0);

  ra.cap_header.version = _LINUX_CAPABILITY_VERSION_3;
  ra.cap_header.pid = syscall(SYS_gettid);
  syscall(SYS_capget, &ra.cap_header, ra.cap_data);

  scoped_strvec(enabled_caps);

  const ntv_t *caps = ntv_get_list(config, "capabilities");
  if(caps != NULL) {
    NTV_FOREACH_TYPE(cap, caps, NTV_STRING) {
      const char *s = cap->ntv_string;
      if(!enable_cap_str(&ra, s)) {
        strvec_push(&enabled_caps, s);
      }
    }
  }

  scoped_char *enabled_caps_str = strvec_join(&enabled_caps, ", ");

  trace(LOG_INFO, "[%s]: Running '%s' UID:%d GID:%d capabilities given: [%s]",
        title, cmd, ra.uid, ra.gid, enabled_caps_str);

  int clone_flags = CLONE_NEWNS | CLONE_NEWIPC | CLONE_NEWUTS;

  if(!ntv_get_int(config, "use_host_pidspace", 0))
    clone_flags |= CLONE_NEWPID;

  size_t stacksize = 1024 * 1024;
  void *stack = mmap(NULL, stacksize, PROT_WRITE | PROT_READ,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  pid_t pid = clone(container_child, stack + stacksize,
                    SIGCHLD | clone_flags, &ra);
  close(ra.ctrl_pipe[1]);
  if(ra.stdout_pipe[1] >= 0)
    close(ra.stdout_pipe[1]);

  munmap(stack, stacksize);
  strvec_reset(&ra.bindmounts);

  // Wait for child to progress until checkpoint where we can continue
  // to release various resources

  char errmsg[4096];
  int errlen = read(ra.ctrl_pipe[0], errmsg, sizeof(errmsg) - 1);
  close(ra.ctrl_pipe[0]);

  if(pid > 0) {
    trace(LOG_NOTICE, "[%s]: Launched as pid %d", title, pid);
  }

  if(pid < 0) {
    trace(LOG_ERR, "[%s]: Clone failed -- %s", title, strerror(errno));
    if(ra.stdout_pipe[0] >= 0)
      close(ra.stdout_pipe[0]);
    pid = 0;
  } else if(errlen > 0) {
    errmsg[errlen] = 0;
    trace(LOG_ERR, "[%s]: Failed to start container -- %s",
          title, errmsg);
    if(ra.stdout_pipe[0] >= 0)
      close(ra.stdout_pipe[0]);

  } else if(ra.stdout_pipe[0] >= 0) {
    redirect_t *redir = calloc(1, sizeof(redirect_t));
    redir->fd = ra.stdout_pipe[0];
    redir->pid = pid;
    redir->name = fmt("console.%s", syslog_name);

    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_t tid;
    pthread_create(&tid, &attr, redirect_thread, redir);
    pthread_attr_destroy(&attr);
  }
  return pid;
}



/**
 *
 */
static int
makenode(const char *root, const char *d, mode_t mode, dev_t dev, err_t **err)
{
  char path[PATH_MAX];
  snprintf(path, sizeof(path), "%s/dev/%s", root, d);
  unlink(path);
  if(mknod(path, mode, dev)) {
    if(errno == EEXIST)
      return 0;

    err_pushsys(err, "Unable to mknod(%s, 0%o, %d:%d)",
             path, mode, major(dev), minor(dev));
    return -1;
  }

  if(chmod(path, mode)) {
    err_pushsys(err, "Unable to chmod(%s,0%o)", path, mode);
    unlink(path);
    return -1;
  }

  int uid = 0;
  int gid = 0;

  if(lchown(path, uid, gid)) {
    err_pushsys(err, "Unable to chown(%s, %d, %d)", path, uid, gid);
    unlink(path);
    return -1;
  }
  return 0;
}


/**
 *
 */
static int
makenodes(const char *root, err_t **err)
{
  if(makenode(root, "null", S_IFCHR | 0666, makedev(1, 3), err))
    return -1;

  if(makenode(root, "zero", S_IFCHR | 0666, makedev(1, 5), err))
    return -1;

  if(makenode(root, "random", S_IFCHR | 0444, makedev(1, 8), err))
    return -1;

  if(makenode(root, "urandom", S_IFCHR | 0444, makedev(1, 9), err))
    return -1;
  return 0;
}


static int
install_image(const char *basepath, const ntv_t *manifest,
              const char *title, const char *git_id,
              const ntv_t *docker_env,
              const ntv_t *docker_config)
{
  trace(LOG_INFO, "[%s]: Installing into directory %s",
        title, basepath);

  scoped_err_t *err = NULL;
  if(docker_image_install(basepath, manifest, &err, docker_config)) {
    scoped_char *errstr = err_str(err);
    trace(LOG_ERR, "[%s]: Failed to install docker image into directory %s -- %s",
          title, basepath, errstr);
    return -1;
  }


  if(makenodes(basepath, &err)) {
    scoped_char *errstr = err_str(err);
    trace(LOG_ERR, "[%s]: Failed setup /dev in directory %s -- %s",
          title, basepath, errstr);
    return -1;
  }
  trace(LOG_INFO, "[%s]: Installed docker image into directory %s",
        title, basepath);

  return 0;
}


static ntv_t *
mapify_env(const ntv_t *envlist)
{
  if(envlist == NULL)
    return NULL;
  ntv_t *r = ntv_create_map();
  NTV_FOREACH_TYPE(e, envlist, NTV_STRING) {
    scoped_char *k = strdup(e->ntv_string);
    char *v = strchr(k, '=');
    if(v == NULL)
      continue;
    *v++ = 0;
    ntv_set_str(r, k, v);
  }
  return r;
}




static int
boot_image(const ntv_t *manifest, container_t *c)
{
  const char *digest = ntv_get_str(manifest, "digest");
  if(digest == NULL) {
    trace(LOG_ERR, "Manifest contains to top level digest");
    return -1;
  }
  scoped_err_t *err = NULL;

  scoped_ntv_t *config = docker_image_get_config(manifest, &err,
                                                 ntv_get_map(c->c_config,
                                                             "docker"));
  if(config == NULL) {
    scoped_char *errstr = err_str(err);
    trace(LOG_ERR, "Failed to get docker image config -- %s",
          errstr);
    return -1;
  }

  const char *manifest_title = ntv_get_str(manifest, "title");
  const ntv_t *config_inner = ntv_get_map(config, "config");
  const char *commit =
    ntv_get_str(ntv_field_from_path(config_inner, (const char *[]){"Labels", "commit", NULL}), NULL);

  scoped_char *title = NULL;

  const char *tag = strchr(manifest_title, ':');
  if(tag != NULL)
    tag++;

  if(commit != NULL && tag != NULL && !mystrbegins(commit, tag)) {
    title = fmt("%s-g%.10s", manifest_title, commit);
  } else {
    title = strdup(manifest_title);
  }

  scoped_char *git_id = commit ? fmt("%.10s", commit) : NULL;

  trace(LOG_INFO, "[%s]: Booting docker image %s", title, digest);
  scoped_ntv_t *docker_env = mapify_env(ntv_get_list(config_inner, "Env"));

  char template[] = "/tmp/frontloader.rootfs.XXXXXX";
  char *dirname = mkdtemp(template);
  if(dirname == NULL) {
    trace(LOG_ERR, "[%s]: Failed to create temporary directory %s -- %s",
          title, template, strerror(errno));
    return -1;
  }
  if(mount("tmpfs", dirname, "tmpfs", 0, "")) {
    trace(LOG_ERR, "[%s]: Failed to mount temporary at %s -- %s",
          title, dirname, strerror(errno));
    rmdir(dirname);
    return -1;
  }

  scoped_ntv_t *local_config = ntv_copy(c->c_config);
  pid_t pid = 0;
  int r = -1;

  if(c->c_want_running) {

    pthread_mutex_unlock(&container_mutex);
    r = install_image(dirname, manifest, title, git_id, docker_env,
                      ntv_get_map(local_config, "docker"));
    pthread_mutex_lock(&container_mutex);
    if(!r && c->c_want_running) {

      c->c_will_start = 1;
      const int debug_exec = c->c_auto_debug_exec;
      if(ntv_get_int(local_config, "stop_before_start", 0)) {

        struct timespec ts = {time(NULL) + 60};

        if(c->c_pid) {
          trace(LOG_INFO, "[%s]: Stopping current process %d",
                title, c->c_pid);

          kill(c->c_pid, SIGTERM);
          while(c->c_pid) {
            if(pthread_cond_timedwait(&c->c_cond, &container_mutex, &ts))
              break;
          }
        }

        if(c->c_pid) {
          kill(c->c_pid, SIGKILL);
          ts.tv_sec = time(NULL) + 5;
          while(c->c_pid) {
            if(pthread_cond_timedwait(&c->c_cond, &container_mutex, &ts))
              break;
          }
        }

        if(c->c_pid) {
          trace(LOG_ERR, "[%s]: Failed to terminate current process",
                title);
          r = 1;
        }
      }

      if(!r) {
        pid = launch(dirname, local_config, title, git_id, docker_env, debug_exec);
        if(pid) {
          intvec_insert_sorted(&allpids, pid);
          c->c_pid = pid;
        } else {
          r = -1;
        }
      }

      c->c_will_start = 0;

    } else {
      r = -1;
    }
  }

  if(umount2(dirname, MNT_DETACH) < 0)
    trace(LOG_ERR, "[%s]: Failed to umount rootfs -- %s", title,
          strerror(errno));

  if(rmdir(dirname) < 0)
    trace(LOG_ERR, "[%s]: Failed to rmdir rootfs -- %s", title,
          strerror(errno));
  return r;
}


static ntv_t *
get_manifest(const ntv_t *config)
{
  const char *url = ntv_get_str(config, "manifest");
  if(url == NULL) {
    trace(LOG_ERR, "No manifest URL in config");
    return NULL;
  }
  scoped_err_t *err = NULL;
  ntv_t *manifest = docker_image_load_manifest(url, &err,
                                               ntv_get_map(config, "docker"));

  if(manifest == NULL) {
    scoped_char *errstr = err_str(err);
    trace(LOG_ERR, "Failed to load manifest from %s -- %s", url, errstr);
  }
  return manifest;
}

struct sigterm_delay {
  pid_t pid;
  int delay;
};

static void *
sigterm_delay_thread(void *aux)
{
  const struct sigterm_delay *sd = aux;
  sleep(sd->delay);
  trace(LOG_INFO, "Terminating old pid %d", (int)sd->pid);
  kill(sd->pid, SIGTERM);
  free(aux);
  return NULL;
}



static int
check_container(container_t *c)
{
  ntv_t *manifest = get_manifest(c->c_config);
  if(manifest == NULL)
    return -1;

  if(!ntv_cmp(c->c_manifest, manifest) && c->c_pid &&
     !c->c_force_restart) {
    ntv_release(manifest);
    return 0;
  }

  const int old_pid = c->c_pid;

  if(boot_image(manifest, c)) {
    // Failed, don't update current manifest cause we want to retry
    ntv_release(manifest);
    return -1;
  }
  c->c_force_restart = 0;

  if(old_pid) {
    const int sigterm_delay = ntv_get_int(c->c_config, "sigterm_delay", 0);
    if(!sigterm_delay) {
      trace(LOG_INFO, "%s: Terminating old pid %d", c->c_id, (int)old_pid);
      kill(old_pid, SIGTERM);
    } else {
      trace(LOG_INFO, "%s: Delaying termination of old pid %d with %d seconds",
            c->c_id, (int)old_pid, sigterm_delay);
      struct sigterm_delay *sd = calloc(1, sizeof(struct sigterm_delay));
      sd->pid = old_pid;
      sd->delay = sigterm_delay;

      pthread_attr_t attr;
      pthread_attr_init(&attr);
      pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
      pthread_t tid;
      pthread_create(&tid, &attr, sigterm_delay_thread, sd);
      pthread_attr_destroy(&attr);
    }
  }

  ntv_release(c->c_manifest);
  c->c_manifest = manifest;
  return 0;
}

static void *
container_thread(void *aux)
{
  container_t *c = aux;
  pthread_mutex_lock(&container_mutex);
  while(c->c_want_running) {
    const int problem = check_container(c);
    if(!c->c_want_running)
      break;

    int sleeptime = problem ? 10 :
      check_interval * (1.0f + drand48() * 0.1f);

    if(sleeptime == 0) {
      pthread_cond_wait(&c->c_cond, &container_mutex);
    } else {
      struct timespec ts = {time(NULL) + sleeptime};
      pthread_cond_timedwait(&c->c_cond, &container_mutex, &ts);
    }
  }
  if(c->c_pid) {
    const int sig = ntv_get_int(c->c_config, "final_signal", SIGTERM);

    trace(LOG_INFO, "%s: Terminating pid %d with signal %d",
          c->c_id, c->c_pid, sig);
    kill(c->c_pid, sig);
  }

  pthread_mutex_unlock(&container_mutex);

  ntv_release(c->c_config);
  ntv_release(c->c_manifest);
  free(c->c_id);
  free(c);
  return NULL;
}


static char *
status2str(int status)
{
  if(WIFEXITED(status))
    return fmt("exited with %d", WEXITSTATUS(status));
  if(WIFSIGNALED(status))
    return fmt("terminated by signal %d%s", WTERMSIG(status),
               WCOREDUMP(status) ? ", core dumped" : "");
  return fmt("status 0x%x", status);
}


static void *
reaper_thread(void *aux)
{
  container_t *c;
  sigset_t set;
  sigemptyset(&set);
  sigaddset(&set, SIGUSR1);
  sigaddset(&set, SIGCHLD);

  while(1) {
    int delivered = 0;
    if(sigwait(&set, &delivered))
      continue;

    if(delivered == SIGUSR1) {

      pthread_mutex_lock(&container_mutex);
      LIST_FOREACH(c, &containers, c_link) {
        c->c_force_restart = 1;
        pthread_cond_signal(&c->c_cond);
      }
      pthread_mutex_unlock(&container_mutex);
    }

    if(delivered == SIGCHLD) {
      pid_t pid;
      int status;
      while((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        scoped_char *str = status2str(status);
        pthread_mutex_lock(&container_mutex);

        const char *info = "";
        const int p = intvec_find(&allpids, pid);
        if(p != -1) {
          intvec_delete(&allpids, p);
          if(allpids.count == 0)
            pthread_cond_signal(&container_allpids_cond);
        } else {
          info = ", pid we didn't know about";
        }

        LIST_FOREACH(c, &containers, c_link) {
          if(c->c_pid == pid) {
            c->c_pid = 0;
            c->c_exit_status = status;
            pthread_cond_signal(&c->c_cond);
            break;
          }
        }
        if(c != NULL) {
          c->c_auto_debug_exec = WIFEXITED(status) && WEXITSTATUS(status) == 127;
        }
        if(c != NULL && c->c_will_start) {
          trace(LOG_INFO,
                "Child exited pid %d %s in stop-before-start mode",
                pid, str);
        } else {
          trace(status ? LOG_ERR : LOG_INFO,
                "Child exit pid %d %s%s%s",
                pid, str,
                c != NULL ? ", container should be running, will restart" : "",
              info);
        }
        pthread_mutex_unlock(&container_mutex);
      }
    }
  }
  return NULL;
}

static void
containers_mark(void)
{
  container_t *c;
  LIST_FOREACH(c, &containers, c_link) {
    c->c_mark = 1;
  }
}


static void
container_add(const ntv_t *config)
{
  container_t *c;

  const char *id = ntv_get_str(config, "id");
  if(id == NULL)
    id = ntv_get_str(config, "manifest");

  if(ntv_get_int(config, "disabled", 0))
    return;

  if(id == NULL) {
    return;
  }

  LIST_FOREACH(c, &containers, c_link) {
    if(!strcmp(c->c_id, id)) {
      break;
    }
  }

  if(c != NULL) {
    c->c_mark = 0;

    if(ntv_cmp(c->c_config, config)) {
      ntv_release(c->c_config);
      c->c_config = ntv_copy(config);
      c->c_force_restart = 1;
      pthread_cond_signal(&c->c_cond);
    }
  } else {
    c = calloc(1, sizeof(container_t));
    c->c_id = strdup(id);
    c->c_config = ntv_copy(config);
    c->c_want_running = 1;
    LIST_INSERT_HEAD(&containers, c, c_link);

    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_t tid;
    pthread_create(&tid, &attr, container_thread, c);
    pthread_attr_destroy(&attr);
  }
}


static void
containers_sweep(void)
{
  container_t *c, *n;
  for(c = LIST_FIRST(&containers); c != NULL; c = n) {
    n = LIST_NEXT(c, c_link);
    if(!c->c_mark)
      continue;
    LIST_REMOVE(c, c_link);
    c->c_want_running = 0;
    pthread_cond_signal(&c->c_cond);
  }
}






static int
runner_reconfigure(const ntv_t *conf)
{
  pthread_mutex_lock(&container_mutex);

  check_interval = ntv_get_int(conf, "check_interval", 600);

  containers_mark();

  const ntv_t *list = ntv_get_list(conf, "containers");
  if(list != NULL) {
    NTV_FOREACH_TYPE(container, list, NTV_MAP) {
      container_add(container);
    }
  }

  const ntv_t *container = ntv_get_map(conf, "container");
  if(container != NULL)
    container_add(container);

  containers_sweep();
  pthread_mutex_unlock(&container_mutex);
  return 0;
}

CONFIG_SUB(runner_reconfigure, "runner", 1000);

static pthread_t reaper_tid;

static void
runner_init(void)
{
  pthread_create(&reaper_tid, NULL, reaper_thread, NULL);
}


static void
runner_fini(void)
{
  pthread_mutex_lock(&container_mutex);

  trace(LOG_INFO, "Waiting for containers to shutdown (%zd pids)", allpids.count);

  containers_mark();
  containers_sweep();

  while(allpids.count)
    pthread_cond_wait(&container_allpids_cond, &container_mutex);

  pthread_mutex_unlock(&container_mutex);

  trace(LOG_INFO, "All containers have stopped");
}


INITME(runner_init, runner_fini, 1000);
