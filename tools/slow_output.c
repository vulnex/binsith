/* macOS-only, benchmark-only write-latency injection. Never linked into BinSith.
 * Build: clang -dynamiclib -O2 -Wall -Wextra -Werror tools/slow_output.c -o /tmp/slow_output.dylib
 * DYLD_INSERT_LIBRARIES selects this library only for benchmark children.
 * Scope: regular descriptors whose resolved path lies below the configured root.
 * This models per-write latency, not bandwidth, fsync, metadata, or physical media.
 */
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <mach-o/dyld.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

static const char *root, *audit;
static size_t root_length;
static unsigned long delay_us;
static _Atomic unsigned long long calls, bytes;

__attribute__((constructor)) static void configure(void) {
    char executable[PATH_MAX], resolved[PATH_MAX];
    uint32_t size = sizeof(executable);
    const char *target = getenv("BINSITH_BENCH_TARGET");
    if (!target || _NSGetExecutablePath(executable, &size)
        || !realpath(executable, resolved) || strcmp(resolved, target)) return;
    root = getenv("BINSITH_BENCH_OUTPUT_ROOT");
    audit = getenv("BINSITH_BENCH_WRITE_AUDIT");
    const char *value = getenv("BINSITH_BENCH_WRITE_DELAY_US");
    if (root && audit && value) {
        root_length = strlen(root);
        char *end;
        delay_us = strtoul(value, &end, 10);
        if (*end || !delay_us || delay_us > 1000000) _exit(125);
    }
}

static void delay_write(int fd, size_t length) {
    if (!delay_us) return;
    int saved_errno = errno;
    char path[PATH_MAX];
    struct stat info;
    if (!fstat(fd, &info) && S_ISREG(info.st_mode) && !fcntl(fd, F_GETPATH, path)
        && !strncmp(path, root, root_length) && path[root_length] == '/') {
        atomic_fetch_add(&calls, 1);
        atomic_fetch_add(&bytes, length);
        struct timespec remaining = {delay_us / 1000000, (delay_us % 1000000) * 1000};
        while (nanosleep(&remaining, &remaining) && errno == EINTR) {}
    }
    errno = saved_errno;
}

static ssize_t delayed_write(int fd, const void *buffer, size_t size) {
    delay_write(fd, size);
    return write(fd, buffer, size);
}
static ssize_t delayed_pwrite(int fd, const void *buffer, size_t size, off_t offset) {
    delay_write(fd, size);
    return pwrite(fd, buffer, size, offset);
}
static ssize_t delayed_writev(int fd, const struct iovec *vectors, int count) {
    size_t size = 0;
    for (int i = 0; i < count; i++) size += vectors[i].iov_len;
    delay_write(fd, size);
    return writev(fd, vectors, count);
}

__attribute__((destructor)) static void record(void) {
    if (!delay_us) return;
    char path[PATH_MAX], data[256];
    int length = snprintf(path, sizeof(path), "%s/%ld.json", audit, (long)getpid());
    if (length < 0 || (size_t)length >= sizeof(path)) _exit(125);
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) _exit(125);
    length = snprintf(data, sizeof(data),
        "{\"calls\":%llu,\"requested_bytes\":%llu,\"delay_us\":%lu}\n",
        atomic_load(&calls), atomic_load(&bytes), delay_us);
    if (write(fd, data, (size_t)length) != length || close(fd)) _exit(125);
}

#define INTERPOSE(replacement, original) \
    __attribute__((used)) static const struct { const void *a, *b; } \
    interpose_##original __attribute__((section("__DATA,__interpose"))) = \
        {(const void *)(uintptr_t)&replacement, (const void *)(uintptr_t)&original}
INTERPOSE(delayed_write, write);
INTERPOSE(delayed_pwrite, pwrite);
INTERPOSE(delayed_writev, writev);
