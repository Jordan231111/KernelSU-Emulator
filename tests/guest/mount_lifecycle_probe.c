#define _GNU_SOURCE
#include <fcntl.h>
#include <grp.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/mount.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc >= 3 && !strcmp(argv[1], "--private-namespace")) {
        if (unshare(CLONE_NEWNS) || mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL)) {
            perror("private mount namespace");
            return 8;
        }
        execvp(argv[2], argv + 2);
        perror("namespace command");
        return 9;
    }
    if (argc < 4) return 2;
    if (argc > 5 && unshare(CLONE_NEWNS)) return 3;
    if (argc > 4) {
        const char *context = "u:r:untrusted_app:s0";
        int attr = open("/proc/self/attr/current", O_WRONLY);
        if (attr < 0 || setgroups(0, NULL) || setgid(19999) || setuid(19999) ||
            write(attr, context, strlen(context)) < 0) return 4;
        close(attr);
        prctl(PR_SET_DUMPABLE, 1);
    }
    /* Read fdinfo FIRST: a mount-table read must not be needed to hide its ID. */
    int fd = open(argv[1], O_RDONLY);
    if (fd < 0) return 5;
    char path[96], line[4096], point[2048];
    snprintf(path, sizeof(path), "/proc/self/fdinfo/%d", fd);
    FILE *input = fopen(path, "r");
    if (!input) return 6;
    unsigned fd_mount = 0;
    while (fgets(line, sizeof(line), input)) sscanf(line, "mnt_id:\t%u", &fd_mount);
    fclose(input);
    input = fopen("/proc/self/mountinfo", "r");
    if (!input) return 7;
    int target = 0, original = 0, fd_visible = 0;
    while (fgets(line, sizeof(line), input)) {
        unsigned id;
        if (sscanf(line, "%u %*s %*s %*s %2047s", &id, point) != 2) continue;
        target += !strcmp(point, argv[2]);
        original += !strcmp(point, argv[3]);
        fd_visible |= id == fd_mount;
    }
    fclose(input);
    close(fd);
    printf("{\"uid\":%u,\"fd_mount\":%u,\"target_visible\":%d,\"original_visible\":%d,\"fd_mount_visible\":%s}\n",
           getuid(), fd_mount, target, original, fd_visible ? "true" : "false");
    return 0;
}
