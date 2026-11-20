#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static struct stat buffers[8];
static atomic_int done, leaks, failures;
static const char *path;
static unsigned long original_inode;

static void *observe(void *unused) {
    (void)unused;
    while (!atomic_load(&done))
        for (int i = 0; i < 8; i++)
            if (__atomic_load_n(&buffers[i].st_ino, __ATOMIC_RELAXED) == original_inode)
                atomic_fetch_add(&leaks, 1);
    return NULL;
}
static void *query(void *arg) {
    struct stat *buffer = arg;
    for (int i = 0; i < 20000; i++)
        if (stat(path, buffer) || buffer->st_ino != 12345 || buffer->st_size != 4242)
            atomic_fetch_add(&failures, 1);
    return NULL;
}
int main(int argc, char **argv) {
    if (argc != 3) return 2;
    path = argv[1]; original_inode = strtoul(argv[2], NULL, 10);
    int context = open("/proc/self/attr/current", O_WRONLY);
    const char *label = "u:r:untrusted_app:s0";
    if (context < 0 || setgroups(0, NULL) || setgid(19999) || setuid(19999)) return 3;
    if (write(context, label, strlen(label)) < 0) return 4;
    close(context);
    pthread_t reader, workers[8];
    if (pthread_create(&reader, NULL, observe, NULL)) return 5;
    for (int i = 0; i < 8; i++)
        if (pthread_create(&workers[i], NULL, query, &buffers[i])) return 6;
    for (int i = 0; i < 8; i++) pthread_join(workers[i], NULL);
    atomic_store(&done, 1); pthread_join(reader, NULL);
    printf("stat_calls=160000 original_inode_observations=%d failures=%d\n",
           atomic_load(&leaks), atomic_load(&failures));
    return atomic_load(&leaks) || atomic_load(&failures);
}
