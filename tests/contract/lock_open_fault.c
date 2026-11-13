/* Test-only injection for Darwin's concurrent O_CREAT/openat ENOENT race. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int real_openat(int fd, const char *path, int flags, mode_t mode) {
#ifdef __APPLE__
    return openat(fd, path, flags, mode);
#else
    int (*next)(int, const char *, int, ...) = dlsym(RTLD_NEXT, "openat");
    return next(fd, path, flags, mode);
#endif
}

static int injected_openat(int fd, const char *path, int flags, va_list args) {
    mode_t mode = flags & O_CREAT ? va_arg(args, int) : 0;
    if (strcmp(path, "token.lock") == 0 && (flags & O_CREAT)) {
        if (getenv("CCS_TEST_PERSISTENT_LOCK_ENOENT")) {
            errno = ENOENT;
            return -1;
        }
        int marker = real_openat(fd, ".lock-fault", O_WRONLY | O_CREAT | O_EXCL, 0600);
        if (marker >= 0) {
            close(marker);
            /* The race winner has already published the lock inode. */
            int lock = real_openat(fd, path, flags, mode);
            if (lock >= 0) close(lock);
            errno = ENOENT;
            return -1;
        }
    }
    return real_openat(fd, path, flags, mode);
}

#ifdef __APPLE__
int fault_openat(int fd, const char *path, int flags, ...) {
#else
int openat(int fd, const char *path, int flags, ...) {
#endif
    va_list args;
    va_start(args, flags);
    int result = injected_openat(fd, path, flags, args);
    va_end(args);
    return result;
}

#ifdef __APPLE__
__attribute__((used)) static struct { const void *replacement; const void *original; }
interpose_openat __attribute__((section("__DATA,__interpose"))) = {
    (const void *)fault_openat, (const void *)openat
};
#endif
