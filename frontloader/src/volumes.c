#define _GNU_SOURCE
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/mman.h>
#include <netdb.h>
#include <inttypes.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mount.h>

#include <linux/nvme_ioctl.h>
#include <linux/dm-ioctl.h>

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <stdio.h>
#include <stdarg.h>
#include <syslog.h>

#include <zlib.h>

#include "libsvc/init.h"
#include "libsvc/misc.h"
#include "libsvc/trace.h"
#include "libsvc/ntv.h"

#include "config.h"

#include "xfsgz.h"



typedef enum volume_type {
  VOLUME_TYPE_XFS,
  VOLUME_TYPE_NFS,
} volume_type_t;



static LIST_HEAD(, volume) volumes;
static pthread_mutex_t volume_mutex;


typedef struct volume {
  LIST_ENTRY(volume) v_link;
  char *v_path;
  char *v_device;
  volume_type_t v_type;
  int v_mark;
  int64_t v_device_size;

  int v_device_fd;
} volume_t;




static int
safe_mount(const char *device, const char *path,
           const char *fstype, const char *options)
{
  if(!mount(device, path, fstype, 0, options))
    return 0;

  if(errno == EBUSY) {
    int flags = MNT_DETACH;
    if(!strcmp(fstype, "nfs"))
      flags |= MNT_FORCE;

    umount2(path, flags);
  }

  if(!mount(device, path, fstype, 0, options))
    return 0;

  return -1;
}


static int
volume_nfs_add(const char *device, const char *path, const char *options)
{
  scoped_char *addr = NULL;
  scoped_char *hostname = strdup(device);
  char *c = strchr(hostname, ':');
  if(c == NULL) {
    trace(LOG_ERR, "Unable to mount %s, Device is not a mount path",
          device);
    return -1;
  }
  *c = 0;

  for(int i = 0; i < 10; i++) {
    struct addrinfo *res = NULL;
    const int gai_err = getaddrinfo(hostname, NULL, NULL, &res);
    if(gai_err) {
      trace(LOG_ERR,
            "Unable to mount %s, Unable to resolve hostname %s -- %s",
            device, hostname, gai_strerror(gai_err));
      sleep(1);
      continue;
    }
    if(res == NULL) {
      trace(LOG_ERR,
            "Unable to mount %s, Unable to resolve hostname %s -- %s",
            device, hostname, "No addresses");
      freeaddrinfo(res);
      sleep(1);
      continue;
    }
    const struct sockaddr_in *sin =
      (const struct sockaddr_in *)res->ai_addr;
    if(sin->sin_family != AF_INET) {
      trace(LOG_ERR,
            "Unable to mount %s, Unable to resolve hostname %s -- %s",
            device, hostname, "Not an IPv4 address");
      freeaddrinfo(res);
      sleep(1);
      continue;
    }

    const uint8_t *ipv4 = (const uint8_t *)&sin->sin_addr;
    addr = fmt("%u.%u.%u.%u", ipv4[0],ipv4[1],ipv4[2],ipv4[3]);
    freeaddrinfo(res);
    break;
  }

  if(addr == NULL) {
    trace(LOG_ERR,
          "Unable to mount %s, Unable to resolve hostname %s -- %s",
          device, hostname, "Giving up");
    return -1;
  }
  scoped_char *options2 = fmt("%s%saddr=%s", options, *options ? "," : "", addr);

  return safe_mount(device, path, "nfs", options2);
}



static int
volume_xfs_add(const char *device, const char *path)
{
  if(!safe_mount(device, path, "xfs", ""))
    return 0;

  if(errno == EBUSY)
    return -1;

  int fd = open(device, O_RDWR);
  if(fd == -1)
    return -1;

  uint8_t bootsector[512];

  if(read(fd, bootsector, sizeof(bootsector)) != sizeof(bootsector)) {
    trace(LOG_INFO, "Unable to check bootsector on %s : %s",
          device, strerror(errno));
    close(fd);
    return -1;
  }

  if(bootsector[510] == 0x55 && bootsector[511] == 0xaa &&
     !memcmp(bootsector + 440, "FLDR", 4)) {
    trace(LOG_INFO,
          "Refusing to format %s -- Contains x86/MBR + Frontloader signature",
          device);
    close(fd);
    return -1;
  }

  const size_t fssize = 16 * 1024 * 1024; // Size of decompressed XFS image

  trace(LOG_INFO, "Creating XFS file system on %s", device);

  void *ptr = mmap(NULL, fssize, PROT_WRITE | PROT_READ, MAP_SHARED, fd, 0);
  close(fd);
  if(ptr == MAP_FAILED)
    return -1;

  z_stream z = {};
  inflateInit2(&z, 16 + MAX_WBITS);

  z.next_in = xfsgz;
  z.avail_in = sizeof(xfsgz);
  z.next_out = ptr;
  z.avail_out = fssize;
  int r = inflate(&z, Z_SYNC_FLUSH);
  munmap(ptr, fssize);

  inflateEnd(&z);
  if(r != Z_STREAM_END) {
    trace(LOG_ERR, "Unable to decompress XFS image onto %s zlib error:%d",
          device, r);
    return -1;
  }

  return mount(device, path, "xfs", 0, "");
}



// From Linux kernel
#define XFS_IOC_FSGROWFSDATA      _IOW ('X', 110, struct xfs_growfs_data)
typedef struct xfs_growfs_data {
  uint64_t           newblocks;      /* new data subvol size, fsblocks */
  uint32_t           imaxpct;        /* new inode space percentage limit */
} xfs_growfs_data_t;


#define XFS_IOC_FSGEOMETRY_V1        _IOR ('X', 100, struct xfs_fsop_geom_v1)

/*
 * Output for XFS_IOC_FSGEOMETRY_V1
 */
typedef struct xfs_fsop_geom_v1 {
        uint32_t           blocksize;      /* filesystem (data) block size */
        uint32_t           rtextsize;      /* realtime extent size         */
        uint32_t           agblocks;       /* fsblocks in an AG            */
        uint32_t           agcount;        /* number of allocation groups  */
        uint32_t           logblocks;      /* fsblocks in the log          */
        uint32_t           sectsize;       /* (data) sector size, bytes    */
        uint32_t           inodesize;      /* inode size in bytes          */
        uint32_t           imaxpct;        /* max allowed inode space(%)   */
        uint64_t           datablocks;     /* fsblocks in data subvolume   */
        uint64_t           rtblocks;       /* fsblocks in realtime subvol  */
        uint64_t           rtextents;      /* rt extents in realtime subvol*/
        uint64_t           logstart;       /* starting fsblock of the log  */
        unsigned char   uuid[16];       /* unique id of the filesystem  */
        uint32_t           sunit;          /* stripe unit, fsblocks        */
        uint32_t           swidth;         /* stripe width, fsblocks       */
         int32_t           version;        /* structure version            */
        uint32_t           flags;          /* superblock version flags     */
        uint32_t           logsectsize;    /* log sector size, bytes       */
        uint32_t           rtsectsize;     /* realtime sector size, bytes  */
        uint32_t           dirblocksize;   /* directory block size, bytes  */
} xfs_fsop_geom_v1_t;



static void
volume_xfs_check(volume_t *v)
{
  if(v->v_device_fd == -1)
    v->v_device_fd = open(v->v_device, O_RDWR);
  if(v->v_device_fd == -1)
    return;

  uint64_t size;
  ioctl(v->v_device_fd, BLKGETSIZE64, &size);

  if(size == v->v_device_size)
    return;

  long mbsize = size / (1024 * 1024);

  int fd = open(v->v_path, O_RDONLY | O_DIRECTORY);
  if(fd == -1) {
    trace(LOG_WARNING, "Unable to open %s for XFS resize: %s",
          v->v_path, strerror(errno));
    return;
  }

  xfs_fsop_geom_v1_t g;
  if(!ioctl(fd, XFS_IOC_FSGEOMETRY_V1, &g)) {

    xfs_growfs_data_t data;
    data.imaxpct = 25; // Max 25% used for inodes, seems default
    data.newblocks = size / g.blocksize;

    if(data.newblocks != g.datablocks) {

      trace(LOG_INFO, "Resizing XFS filesystem on %s (%s) to %ld MB",
            v->v_path, v->v_device, mbsize);

      int r = ioctl(fd, XFS_IOC_FSGROWFSDATA, &data);
      if(r) {
        trace(LOG_WARNING, "Resizing XFS filesystem on %s (%s) to %ld MB FAILED: %s",
              v->v_path, v->v_device, mbsize, strerror(errno));
      } else {
        trace(LOG_INFO, "Resizing XFS filesystem on %s (%s) to %ld MB DONE",
              v->v_path, v->v_device, mbsize);
        v->v_device_size = size;
      }
    } else {
      v->v_device_size = size;
    }
  }
  close(fd);
}


static void
volume_check(volume_t *v)
{
  switch(v->v_type) {
  case VOLUME_TYPE_XFS:
    volume_xfs_check(v);
    break;
  default:
    break;
  }
}



static int
volume_add(const char *device, const char *path,
           volume_type_t fstype, const char *options)
{
  volume_t *v;
  LIST_FOREACH(v, &volumes, v_link) {
    if(!strcmp(v->v_path, path)) {
      v->v_mark = 0;
      return 0;
    }
  }

  mkdir_p(path, 0775);

  int r;
  switch(fstype) {
  case VOLUME_TYPE_XFS:
    r = volume_xfs_add(device, path);
    break;
  case VOLUME_TYPE_NFS:
    r = volume_nfs_add(device, path, options);
    break;
  }

  trace(r ? LOG_ERR : LOG_INFO,
        "Mounted %s at %s : %s", device, path, r ? strerror(errno) : "OK");

  if(r) {
    // XXX frontloader_shutdown()
    return -1;
  }

  v = calloc(1, sizeof(volume_t));
  v->v_device_fd = -1;
  v->v_path = strdup(path);
  v->v_device = strdup(device);
  v->v_type = fstype;
  LIST_INSERT_HEAD(&volumes, v, v_link);

  volume_check(v);
  return 0;
}


static void
volumes_mark(void)
{
  volume_t *v;
  LIST_FOREACH(v, &volumes, v_link) {
    v->v_mark = 1;
  }
}


static void
volumes_sweep(void)
{
  volume_t *v, *n;

  for(v = LIST_FIRST(&volumes); v != NULL; v = n) {
    n = LIST_NEXT(v, v_link);
    if(!v->v_mark)
      continue;

    if(v->v_device_fd != -1)
      close(v->v_device_fd);

    int flags = MNT_DETACH;
    if(v->v_type == VOLUME_TYPE_NFS)
      flags |= MNT_FORCE;

    int r = umount2(v->v_path, flags);
    trace(LOG_INFO, "Unmounted %s (%s) : %s",
          v->v_path, v->v_device, r ? strerror(errno) : "OK");
    free(v->v_path);
    free(v->v_device);
    free(v);
  }

}



/**
 * AWS EC2 responds with the "old style" /dev/sdX name in the NVME controller
 * vendor specific data at 0xc00
 *
 * DATA: 0x000c00: 73 64 61 31 20 20 20 20  20 20 20 20 20 20 20 20    sda1
 * DATA: 0x000c10: 20 20 20 20 20 20 20 20  20 20 20 20 20 20 20 20
 *
 * https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/nvme-ebs-volumes.html
 *
 */

static const char *resolve_ec2boot_volume(void);

static const char *
resolve_ec2_volume_name(const char *name)
{
  if(!strcmp(name, "boot"))
    return resolve_ec2boot_volume();

  static char __thread dev[64];
  char data[4096];
  for(int i = 0; i < 1024; i++) {
    snprintf(dev, sizeof(dev), "/dev/nvme%dn1", i);
    int fd = open(dev, O_RDWR);
    if(fd == -1)
      continue;

    struct nvme_admin_cmd cmd = {
      .opcode = 0x06,
      .addr = (intptr_t)data,
      .data_len = sizeof(data),
      .cdw10 = 1
    };

    int r = ioctl(fd, NVME_IOCTL_ADMIN_CMD, &cmd);
    close(fd);
    if(r) {
      trace(LOG_ERR, "Unable to read NVME controller info on %s -- %s",
            dev, strerror(errno));
      continue;
    }

    // Since 32 bytes buffer is not \x00 terminated, make it so on first space
    char *p = &data[0xc00];
    p[32] = 0; // Make sure it's really \x00 terminated
    for(int j = 0; j < 32; j++) {
      if(p[j] == 0x20) {
        p[j] = 0;
        break;
      }
    }

    if(!strcmp(p, name))
      return dev;

    // Local NVME just have empty string as the vendor specific data
    if(!strcmp(name, "ephemeral0") && !strcmp(p, ""))
      return dev;
  }
  trace(LOG_ERR, "Unable to find EC2 volume: %s", name);
  return NULL;
}


static const char *
resolve_ec2boot_volume(void)
{
  struct stat bootdev_st;

  if(!stat("/dev/dm-0", &bootdev_st))
    return "/dev/dm-0"; // Mapped already

  const char *bootdev = "/dev/sda1";

  if(stat(bootdev, &bootdev_st)) {
    bootdev = resolve_ec2_volume_name("sda1");
    if(bootdev == NULL) {
      trace(LOG_ERR, "Unable to find boot device");
      return NULL;
    }
    if(stat(bootdev, &bootdev_st)) {
      trace(LOG_ERR, "Unable to stat device %s", bootdev);
      return NULL;
    }
  }


  uint64_t bootdev_size;

  int bootdev_fd = open(bootdev, O_RDWR);
  if(bootdev_fd == -1) {
    trace(LOG_ERR, "Unable to open device %s -- %s", bootdev,
          strerror(errno));
    return NULL;
  }

  if(ioctl(bootdev_fd, BLKGETSIZE64, &bootdev_size)) {
    trace(LOG_ERR, "Unable to get device %s size -- %s", bootdev,
          strerror(errno));
    close(bootdev_fd);
    return NULL;
  }


  close(bootdev_fd);

  trace(LOG_INFO, "Found boot device: %s device: %d:%d size: %"PRIu64"MB",
        bootdev,
        major(bootdev_st.st_rdev),
        minor(bootdev_st.st_rdev), bootdev_size / (1024 * 1024));

  if(bootdev_size < 128 * 1024 * 1024) {
    trace(LOG_ERR, "Found boot device %s is too small < 128 MB, something is wrong",
          bootdev);
    return NULL;
  }

  const int dmfd = open("/dev/mapper/control", O_RDWR);
  if(dmfd == -1) {
    trace(LOG_ERR, "Unable to open device mapper: %s", strerror(errno));
    return NULL;
  }

  size_t size = 1024 * 16;

  struct dm_ioctl *dmi = alloca(size);
  memset(dmi, 0, size);
  struct dm_target_spec *dts = (struct dm_target_spec *)&dmi[1];
  dmi->version[0] = 4;
  dmi->version[1] = 0;
  dmi->version[2] = 0;
  dmi->data_size = size;
  dmi->data_start = sizeof(*dmi);

  if(ioctl(dmfd, DM_VERSION, dmi) < 0) {
    trace(LOG_ERR, "dm: Unable to get device mapper version: %s",
          strerror(errno));
    close(dmfd);
    return NULL;
  }

  dmi->data_size = size;
  dmi->data_start = sizeof(*dmi);
  dmi->dev = 0;
  strcpy(dmi->name, "boot");

  if(ioctl(dmfd, DM_DEV_CREATE, dmi) < 0) {
    trace(LOG_ERR, "dm: Unable to create mapped device -- %s",
          strerror(errno));
    close(dmfd);
    return NULL;
  }

  uint64_t bootdev_start = 64 * 1024 * 1024;

  dts->sector_start = 0; // 64 * 1024 * 1024 / 512;
  dts->length = (bootdev_size - bootdev_start) / 512;
  strcpy(dts->target_type, "linear");

  char *parameter = (char *)&dts[1];
  int len = snprintf(parameter, size - (sizeof(*dmi) + sizeof(*dts)),
                     "%d:%d %"PRIu64,
                     major(bootdev_st.st_rdev),
                     minor(bootdev_st.st_rdev),
                     bootdev_start / 512);

  len++;
  len += sizeof(*dts);
  len += 7;
  len &= ~7;
  dts->next = len;

  dmi->data_size = size;
  dmi->data_start = sizeof(*dmi);
  dmi->target_count = 1;
  dmi->dev = 0;
  dmi->flags = 0;
  strcpy(dmi->name, "boot");
  if(ioctl(dmfd, DM_TABLE_LOAD, dmi) < 0) {
    trace(LOG_ERR, "dm: Unable to load mapping table -- %s",
          strerror(errno));
    close(dmfd);
    return NULL;
  }

  dmi->data_size = size;
  dmi->data_start = sizeof(*dmi);
  dmi->target_count = 1;
  dmi->dev = 0;
  strcpy(dmi->name, "boot");

  if(ioctl(dmfd, DM_DEV_SUSPEND, dmi) < 0) {
    trace(LOG_ERR, "dm: Unable to enable device -- %s",
          strerror(errno));
    close(dmfd);
    return NULL;
  }

  return "/dev/dm-0";
}



static int
volumes_reconfigure(const ntv_t *conf)
{
  pthread_mutex_lock(&volume_mutex);

  volumes_mark();

  const ntv_t *volumes = ntv_get_list(conf, "volumes");
  if(volumes != NULL) {

    NTV_FOREACH_TYPE(v, volumes, NTV_MAP) {
      const char *device = ntv_get_str(v, "device");
      const char *path   = ntv_get_str(v, "path");
      const char *fstypestr = ntv_get_str(v, "fstype");
      const char *options = ntv_get_str(v, "options") ?: "";
      uid_t uid = ntv_get_int(v, "uid", 0);
      uid_t gid = ntv_get_int(v, "gid", 0);

      if(device == NULL || path == NULL)
        continue;

      const char *ec2 = mystrbegins(device, "ec2:");
      if(ec2 != NULL) {
        device = resolve_ec2_volume_name(ec2);
        if(device == NULL)
          continue;
        trace(LOG_INFO, "Resolved volume ec2:%s to %s", ec2, device);
      }


      volume_type_t fstype;

      if(fstypestr == NULL || !strcmp(fstypestr, "xfs")) {
        fstype = VOLUME_TYPE_XFS;
      } else if(!strcmp(fstypestr, "nfs")) {
        fstype = VOLUME_TYPE_NFS;
      } else {
        continue;
      }

      if(volume_add(device, path, fstype, options))
        continue;

      if(chown(path, uid, gid)) {
        trace(LOG_ERR, "Unable to change owner of %s to %u:%u",
              path, (uint32_t)uid, (uint32_t)gid);
      }
      const ntv_t *dirs = ntv_get_list(v, "mkdir");
      if(dirs != NULL) {
        int dirfd = open(path, O_PATH | O_RDWR);
        if(dirfd == -1) {
          trace(LOG_ERR, "Unable to open %s as directory -- %s",
                path, strerror(errno));
        } else {
          NTV_FOREACH_TYPE(dir, dirs, NTV_STRING) {
            if(mkdirat(dirfd, dir->ntv_string, 0755) && errno != EEXIST) {
              trace(LOG_ERR, "Unable to mkdir %s/%s -- %s",
                    path, dir->ntv_string, strerror(errno));
              continue;
            }
            if(fchownat(dirfd, dir->ntv_string, uid, gid, 0)) {
              trace(LOG_ERR, "Unable to change owner of %s/%s to %u:%u",
                    path, dir->ntv_string, (uint32_t)uid, (uint32_t)gid);
            }
          }
          close(dirfd);
        }
      }
    }
  }
  volumes_sweep();
  pthread_mutex_unlock(&volume_mutex);
  return 0;
}



static void *
volume_thread(void *aux)
{
  while(1) {
    pthread_mutex_lock(&volume_mutex);

    volume_t *v;
    LIST_FOREACH(v, &volumes, v_link) {
      volume_check(v);
    }
    pthread_mutex_unlock(&volume_mutex);
    sleep(1);
  }
  return NULL;
}


CONFIG_SUB(volumes_reconfigure, "volumes", 900);

static void
volumes_init(void)
{
  pthread_attr_t attr;
  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
  pthread_t tid;
  pthread_create(&tid, &attr, volume_thread, NULL);
  pthread_attr_destroy(&attr);
}



static void
volumes_fini(void)
{
  trace(LOG_INFO, "Unmounting all volumes");
  pthread_mutex_lock(&volume_mutex);
  volumes_mark();
  volumes_sweep();
  pthread_mutex_unlock(&volume_mutex);
  trace(LOG_INFO, "Unmounted all volumes");
}



INITME(volumes_init, volumes_fini, 10);
