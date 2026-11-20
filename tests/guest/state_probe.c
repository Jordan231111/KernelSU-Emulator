#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/utsname.h>
#include <unistd.h>

static int drop(void) {
    const char *context = "u:r:untrusted_app:s0";
    int fd = open("/proc/self/attr/current", O_WRONLY);
    if (fd < 0 || setgroups(0, NULL) || setgid(19999) || setuid(19999)) return -1;
    int result = write(fd, context, strlen(context)) == (ssize_t)strlen(context) ? 0 : -1;
    close(fd);
    return result;
}

int main(int argc, char **argv) {
    if (argc < 3) return 2;
    if (!strcmp(argv[1], "app") && drop()) { perror("drop"); return 3; }
    printf("uid=%u\n", getuid());
    if (!strcmp(argv[2], "uid_filter") && argc == 5) {
        static struct { char packages[65535]; int err; } request;
        snprintf(request.packages, sizeof(request.packages), "%s", argv[4]);
        request.err = 126;
        errno = 0;
        long result = syscall(SYS_reboot, 0xDEADBEEF, 0xFAFAFAFA, strtoul(argv[3], NULL, 0), &request);
        printf("reboot_result=%ld errno=%d command_error=%d\n", result, errno, request.err);
        return request.err != 0;
    } else if (!strcmp(argv[2], "hold") && argc == 4) {
        uid_t uid = strtoul(argv[3], NULL, 10);
        if (setgroups(0, NULL) || setgid(uid) || setuid(uid)) return 8;
        sleep(120);
    } else if (!strcmp(argv[2], "priority") && argc == 4) {
        int uid = atoi(argv[3]);
        errno = 0; int result = getpriority(PRIO_USER, uid);
        printf("getpriority=%d errno=%d\n", result, errno);
        errno = 0; result = setpriority(PRIO_USER, uid, 0);
        printf("setpriority=%d errno=%d\n", result, errno);
        errno = 0; result = syscall(SYS_ioprio_get, 3, uid);
        printf("ioprio_get=%d errno=%d\n", result, errno);
        errno = 0; result = syscall(SYS_ioprio_set, 3, uid, 0);
        printf("ioprio_set=%d errno=%d\n", result, errno);
    } else if (!strcmp(argv[2], "uname")) {
        struct utsname info;
        if (uname(&info)) return 4;
        printf("release=%s\nversion=%s\n", info.release, info.version);
    } else if (!strcmp(argv[2], "statfs") && argc == 4) {
        struct statfs info;
        if (statfs(argv[3], &info)) { perror("statfs"); return 5; }
        printf("type=%lx flags=%lx\n", (unsigned long)info.f_type, (unsigned long)info.f_flags);
    } else if (!strcmp(argv[2], "watch") && argc == 5) {
        int events = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
        if (events < 0 || inotify_add_watch(events, argv[3], IN_OPEN) < 0) {
            perror("watch"); return 6;
        }
        int fd = open(argv[4], O_RDONLY);
        if (fd < 0) { perror("open"); return 7; }
        close(fd);
        char buffer[1024] __attribute__((aligned(8)));
        ssize_t size = read(events, buffer, sizeof(buffer));
        printf("notify_bytes=%zd mask=%x\n", size,
               size >= (ssize_t)sizeof(struct inotify_event) ? ((struct inotify_event *)buffer)->mask : 0);
        close(events);
    } else if (!strcmp(argv[2], "create") && argc == 4) {
        char path[512];
        int failures = 0;
        for (int i = 0; i < 100; ++i) {
            snprintf(path, sizeof(path), "%s/new-%d", argv[3], i);
            if (mkdir(path, 0700) || rmdir(path)) ++failures;
            snprintf(path, sizeof(path), "%s/absent/child", argv[3]);
            errno = 0;
            if (mkdir(path, 0700) != -1 || errno != ENOENT) ++failures;
        }
        printf("create_cycles=100 failures=%d\n", failures);
        return failures != 0;
    } else return 2;
    return 0;
}
