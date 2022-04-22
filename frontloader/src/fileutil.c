#include <stdlib.h>
#include <sys/stat.h>
#include <limits.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <archive.h>
#include <archive_entry.h>

#include "libsvc/http_client.h"
#include "libsvc/cfg.h"
#include "libsvc/talloc.h"
#include "libsvc/misc.h"
#include "libsvc/ntv.h"
#include "libsvc/trace.h"
#include "libsvc/memstream.h"
#include "libsvc/err.h"

#include "fileutil.h"

const static int
safe_entry(const char *p)
{
  if(strstr(p, "/../"))
    return 0;
  if(!memcmp(p, "../", 3))
    return 0;
  return 1;
}


static int
file_extract_from_archive(struct archive *a, const char *target,
                          int set_owner, int strip_path_components,
                          int handle_wh, err_t **err)
{

  struct archive_entry *entry;
  const char *oldpath;
  char path[PATH_MAX];

  while(1) {

    int res = archive_read_next_header(a, &entry);

    if(res == ARCHIVE_EOF) {
      break;
    }
    const char *fname = archive_entry_pathname(entry);

    if(res < ARCHIVE_WARN) {
      err_push(err, "%s: %s", fname, archive_error_string(a));
      return -1;
    }

    int fd;
    int64_t size;

    for(int i = 0; i < strip_path_components; i++) {
      fname = strchr(fname, '/');
      if(fname == NULL)
        break;
    }
    if(fname == NULL)
      continue;

    if(!safe_entry(fname)) {
      err_push(err, "%s: Suspicious archive entry", fname);
      return -1;
    }

    snprintf(path, sizeof(path), "%s/%s", target, fname);
    int do_chmod = 0;
    int do_chown = 0;

    if(handle_wh) {
      const char *basename = strrchr(fname, '/');
      if(basename != NULL) {
        basename++;
      } else {
        basename = fname;
      }
      const char *delete = mystrbegins(basename, ".wh.");
      if(delete != NULL) {

        if(basename != fname) {
          snprintf(path, sizeof(path), "%s/%.*s%s", target,
                   (int)(basename - fname), fname, delete);
        } else {
          snprintf(path, sizeof(path), "%s/%s", target, delete);
        }
        if(unlink(path) && errno != ENOENT && rm_rf(path, 1)) {
          err_push(err, "Unable to delete %s -- %s",
                   path, strerror(errno));
          return -1;
        }
        continue;
      }
    }

    const char *hl = archive_entry_hardlink(entry);
    if(hl != NULL) {

      char path2[PATH_MAX];

      if(!safe_entry(hl)) {
        err_push(err, "%s: Suspicious archive entry", fname);
        return -1;
      }

      snprintf(path2, sizeof(path2), "%s/%s", target, hl);
      if(link(path2, path) && errno == EEXIST &&
         unlink(path) && link(path2, path)) {
        err_push(err, "Unable to link(%s, %s) -- %s",
                 path2, path, strerror(errno));
        return -1;
      }
      continue;
    }

    switch(archive_entry_filetype(entry)) {

    case AE_IFCHR:
    case AE_IFBLK:
      continue;

    case AE_IFDIR:
      if(mkdir(path, 0) && errno != EEXIST) {
        err_push(err, "Unable to mkdir(%s) -- %s",
                 path, strerror(errno));
        return -1;
      }
      do_chmod = 1;
      do_chown = 1;
      break;

    case AE_IFLNK:
      oldpath = archive_entry_symlink(entry);
      unlink(path);
      if(symlink(oldpath, path)) {
        err_push(err, "Unable to symlink(%s, %s) -- %s",
                 oldpath, path, strerror(errno));
        return -1;
      }
      do_chown = 1;
      break;

    case AE_IFREG:
      size = archive_entry_size(entry);
      void *mem = malloc(size);
      if(mem == NULL) {
        err_pushsys(err, "Out of memory");
        return -1;
      }

      if(archive_read_data(a, mem, size) != size) {
        err_push(err, "Unable to read data");
        free(mem);
        return -1;
      }

      fd = open(path, O_CLOEXEC | O_CREAT | O_TRUNC | O_NOFOLLOW | O_WRONLY,
                0600);
      if(fd == -1) {
        err_pushsys(err, "Unable to open %s", path);
        free(mem);
        return -1;
      }
      int64_t offset = 0;
      while(offset < size) {
        ssize_t written = write(fd, mem + offset, size - offset);
        if(written <= 0) {
          err_pushsys(err, "Unable to write to %s", path);
          close(fd);
          free(mem);
          return -1;
        }
        offset += written;
      }

      close(fd);
      free(mem);
      do_chmod = 1;
      do_chown = 1;
      break;

    default:
      err_push(err, "Unable to handle filetype 0%o",
               archive_entry_filetype(entry));
      return -1;

    }

    if(do_chmod) {
      mode_t mode = archive_entry_perm(entry);

      if(chmod(path, mode)) {
        err_pushsys(err, "Unable to chmod(%s,0%o)",
                    path, mode);
        return -1;
      }
    }

    if(do_chown && set_owner) {
      uid_t owner = archive_entry_uid(entry);
      gid_t group = archive_entry_gid(entry);
      if(lchown(path, owner, group)) {
        err_pushsys(err, "Unable to chown(%s,%d,%d)",
                    path, owner, group);
        return -1;
      }
    }
  }
  return 0;
}


/**
 *
 */
int
file_extract_from_FILE(FILE *source, const char *target,
                       int set_owner, int strip_path_components, int handle_wh,
                       err_t **err)
{
  struct archive *a = archive_read_new();
  archive_read_support_compression_all(a);
  archive_read_support_format_all(a);
  archive_read_support_filter_all(a);

  int r = archive_read_open_FILE(a, source);

  if(r) {
    err_push(err, "%s", archive_error_string(a));
    archive_read_free(a);
    return -1;
  }

  r = file_extract_from_archive(a, target, set_owner,
                                strip_path_components, handle_wh, err);
  archive_read_free(a);
  return r;
}


/**
 *
 */
int
file_download_extract(const char *source, const char *target,
                      int set_owner, int strip_path_components,
                      err_t **err)
{
  FILE *fp = http_read_file(source, NULL, NULL, 0);
  if(fp == NULL) {
    err_push(err, "Unable to download %s", source);
    return -1;
  }

  if(file_extract_from_FILE(fp, target, 1, 0, 0, err)) {
    err_push(err, "Unable to extract archive from %s", source);
    fclose(fp);
    return -1;
  }
  fclose(fp);
  return 0;
}
