/* SPDX-License-Identifier: MIT
 * Verify the KernelSU ioctl protocol, independently of vendor su and the APK.
 */
#include <errno.h>
#include <grp.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

struct ksu_info { uint32_t version, flags, features, uapi_version; };

int main(int argc, char **argv) {
    if ((argc == 2 || argc == 3) && strcmp(argv[1], "shell-su") == 0) {
        if (getuid() == 0 && (setgroups(0, NULL) || setgid(2000) || setuid(2000))) {
            perror("drop privileges");
            return 2;
        }
        printf("before_su_uid=%u\n", (unsigned)getuid());
        fflush(stdout);
        execl("/system/bin/su", "su", "-c", argc == 3 ? argv[2] : "id; id -Z", (char *)NULL);
        perror("su");
        return 3;
    }
    int fd = -1;
    /* The normal reboot syscall rejects this magic; the KSU hook supplies fd. */
    syscall(__NR_reboot, 0xdeadbeefUL, 0xcafebabeUL, 0UL, &fd);
    if (fd < 0) {
        fprintf(stderr, "KernelSU did not supply a control fd for uid %u\n", (unsigned)getuid());
        return 1;
    }
    struct ksu_info info = {0};
    int result = ioctl(fd, _IOC(_IOC_READ, 'K', 2, sizeof(info)), &info);
    close(fd);
    if (result != 0 || info.version == 0) {
        perror("KernelSU GET_INFO");
        return 1;
    }
    printf("{\"version\":%u,\"flags\":%u,\"uapi\":%u,\"uid\":%u}\n",
           info.version, info.flags, info.uapi_version, (unsigned)getuid());
    return 0;
}
