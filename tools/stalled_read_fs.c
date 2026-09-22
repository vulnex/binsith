/* Test-only Linux FUSE filesystem: one regular input whose read waits for release.
 * Build against libfuse3; mount only a newly created private empty directory.
 * Control files live outside the mount. No real input files are exposed. */
#define FUSE_USE_VERSION 31
#include <fuse3/fuse.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static char blocked[PATH_MAX], release_path[PATH_MAX];
static const off_t input_size = 1024 * 1024;

static int attributes(const char *path, struct stat *st, struct fuse_file_info *fi) {
    (void)fi;
    memset(st, 0, sizeof(*st));
    st->st_uid = getuid(); st->st_gid = getgid();
    st->st_atime = st->st_mtime = st->st_ctime = 1700000000;
    if (!strcmp(path, "/")) {
        st->st_mode = S_IFDIR | 0700; st->st_nlink = 2; st->st_ino = 1;
    } else if (!strcmp(path, "/blocked.bin")) {
        st->st_mode = S_IFREG | 0400; st->st_nlink = 1; st->st_ino = 2;
        st->st_size = input_size;
    } else return -ENOENT;
    return 0;
}
static int entries(const char *path, void *buffer, fuse_fill_dir_t fill,
                   off_t offset, struct fuse_file_info *fi, enum fuse_readdir_flags flags) {
    (void)offset; (void)fi; (void)flags;
    if (strcmp(path, "/")) return -ENOENT;
    fill(buffer, ".", NULL, 0, 0); fill(buffer, "..", NULL, 0, 0);
    fill(buffer, "blocked.bin", NULL, 0, 0);
    return 0;
}
static int open_input(const char *path, struct fuse_file_info *fi) {
    if (strcmp(path, "/blocked.bin")) return -ENOENT;
    if ((fi->flags & O_ACCMODE) != O_RDONLY) return -EACCES;
    fi->direct_io = 1;
    return 0;
}
static int read_input(const char *path, char *buffer, size_t size,
                      off_t offset, struct fuse_file_info *fi) {
    (void)fi;
    if (strcmp(path, "/blocked.bin")) return -ENOENT;
    int marker = open(blocked, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (marker >= 0) close(marker);
    else if (errno != EEXIST) return -EIO;
    /* The scanner is waiting in the kernel for this real FUSE read response. */
    while (access(release_path, F_OK) != 0) {
        if (errno != ENOENT) return -EIO;
        usleep(10000);
    }
    if (offset < 0) return -EINVAL;
    if (offset >= input_size) return 0;
    if (size > (size_t)(input_size - offset)) size = (size_t)(input_size - offset);
    memset(buffer, 'A', size);
    return (int)size;
}
int main(int argc, char **argv) {
    const char *control = getenv("BINSITH_STALL_CONTROL");
    if (!control || control[0] != '/' ||
        snprintf(blocked, sizeof(blocked), "%s/blocked", control) >= (int)sizeof(blocked) ||
        snprintf(release_path, sizeof(release_path), "%s/release", control) >= (int)sizeof(release_path)) {
        fputs("Absolute BINSITH_STALL_CONTROL required\n", stderr); return 2;
    }
    const struct fuse_operations operations = {
        .getattr = attributes, .readdir = entries, .open = open_input, .read = read_input
    };
    return fuse_main(argc, argv, &operations, NULL);
}
