/* Controlled identities for the MuMu Disk Cleanup integration tests. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/capability.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 2 || getuid() != 0) return 2;
    int app = !strcmp(argv[1], "app") || !strcmp(argv[1], "app-socket");
    uid_t uid = app ? 19999 : 1000;
    if (setgroups(0, NULL) || setgid(uid) || setuid(uid)) return 3;
    int attr = open("/proc/self/attr/current", O_WRONLY);
    const char *context = app ? "u:r:app_zygote:s0" : "u:r:system_app:s0";
    if (attr < 0 || write(attr, context, strlen(context)) != (ssize_t)strlen(context)) return 4;
    close(attr);
    struct __user_cap_header_struct h = { .version = _LINUX_CAPABILITY_VERSION_3 };
    struct __user_cap_data_struct c[2] = {{0}};
    if (syscall(__NR_capget, &h, c) || c[0].effective || c[1].effective) return 5;
    printf("uid=%u capabilities=0 context=%s\n", getuid(), context);
    fflush(stdout);
    if (!strcmp(argv[1], "disconnect") || !strcmp(argv[1], "app-socket")) {
        int fd = socket(AF_UNIX, SOCK_STREAM, 0);
        struct sockaddr_un address = { .sun_family = AF_UNIX };
        strcpy(address.sun_path, "/dev/socket/mumu_disk_cleanup");
        int result = connect(fd, (struct sockaddr *)&address, sizeof(address));
        int error = result ? errno : 0;
        printf("connect=%d errno=%d\n", result, error);
        if (!result && write(fd, "T", 1) != 1) return 12;
        close(fd);
        return app ? (result == -1 && error == ENOENT ? 0 : 6) : (result ? 7 : 0);
    }
    prctl(PR_SET_NAME, !strcmp(argv[1], "other-system") ? "cleanup-probe" : "pi_android.nemu");
    int child = fork();
    if (child < 0) return 8;
    if (!child) {
        prctl(PR_SET_NAME, "Binder:qa");
        execl("/system/xbin/mu_bak", "su", NULL);
        int error = errno;
        printf("exec_errno=%d\n", error);
        fflush(stdout);
        _exit(error == ENOENT ? 9 : 17);
    }
    int status;
    if (waitpid(child, &status, 0) != child) return 10;
    return WIFEXITED(status) ? WEXITSTATUS(status) : 11;
}
