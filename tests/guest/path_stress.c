#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

/* Observe a shared getdents buffer while the kernel fills it. A filter applied
 * only after copying to userspace can expose a name to the observer thread. */
static unsigned char buffer[65536];
static atomic_int done, leaks, failures;
static const char *directory, *hidden;
static const char marker[] = "ksu_hidden_probe_marker";

static void *observe(void *unused) {
    (void)unused;
    while (!atomic_load(&done)) {
        for (size_t i = 0; i < sizeof(buffer) - sizeof(marker); i++) {
            if (__atomic_load_n(buffer + i, __ATOMIC_RELAXED) != marker[0]) continue;
            size_t j;
            for (j = 1; j < sizeof(marker) - 1; j++)
                if (__atomic_load_n(buffer + i + j, __ATOMIC_RELAXED) != marker[j]) break;
            if (j == sizeof(marker) - 1) atomic_fetch_add(&leaks, 1);
        }
    }
    return NULL;
}

static void *path_worker(void *unused) {
    (void)unused;
    for (int i = 0; i < 3000; i++) {
        struct stat st;
        if (stat(hidden, &st) != -1 || errno != ENOENT) atomic_fetch_add(&failures, 1);
        int fd = open(hidden, O_PATH);
        if (fd != -1 || errno != ENOENT) atomic_fetch_add(&failures, 1);
        if (fd >= 0) close(fd);
        fd = open(hidden, O_RDONLY);
        if (fd != -1 || errno != ENOENT) atomic_fetch_add(&failures, 1);
        if (fd >= 0) close(fd);
    }
    return NULL;
}

int main(int argc, char **argv) {
    if (argc != 3) return 2;
    directory = argv[1]; hidden = argv[2];
    int context = open("/proc/self/attr/current", O_WRONLY);
    const char *label = "u:r:untrusted_app:s0";
    if (context < 0 || setgroups(0, NULL) || setgid(19999) || setuid(19999)) return 3;
    if (write(context, label, strlen(label)) < 0) return 4;
    close(context);
    pthread_t reader, workers[8];
    if (pthread_create(&reader, NULL, observe, NULL)) return 5;
    for (int i = 0; i < 8; i++)
        if (pthread_create(workers + i, NULL, path_worker, NULL)) return 6;
    int fd = open(directory, O_RDONLY | O_DIRECTORY);
    if (fd < 0) return 7;
    for (int i = 0; i < 10000; i++) {
        if (lseek(fd, 0, SEEK_SET) < 0 || syscall(SYS_getdents64, fd, buffer, sizeof(buffer)) <= 0)
            atomic_fetch_add(&failures, 1);
    }
    close(fd);
    for (int i = 0; i < 8; i++) pthread_join(workers[i], NULL);
    atomic_store(&done, 1);
    pthread_join(reader, NULL);
    printf("uid=%u path_operations=72000 directory_reads=10000 leaked_names=%d failures=%d\n",
           getuid(), atomic_load(&leaks), atomic_load(&failures));
    return atomic_load(&leaks) || atomic_load(&failures) ? 1 : 0;
}
