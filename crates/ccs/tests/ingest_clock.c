/* Test-only monotonic clock offset. Real time and production code are untouched. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int clock_gettime(clockid_t id, struct timespec *ts) {
    static int (*original)(clockid_t, struct timespec *);
    if (!original) original = dlsym(RTLD_NEXT, "clock_gettime");
    int result = original(id, ts);
    const char *path = getenv("CCS_TEST_CLOCK_FILE");
    if (result == 0 && id == CLOCK_MONOTONIC && path) {
        FILE *file = fopen(path, "r");
        long seconds = 0;
        if (file) {
            if (fscanf(file, "%ld", &seconds) == 1) ts->tv_sec += seconds;
            fclose(file);
        }
    }
    return result;
}
