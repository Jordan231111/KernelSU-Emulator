/* SPDX-License-Identifier: GPL-2.0-only
 * MuMu's system-UID API sends one fixed shell request to su for Disk Cleanup.
 * The service performs FITRIM only on its already-open /data directory.
 * It neither interprets shell text nor accepts a caller-chosen path.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/audit.h>
#include <linux/capability.h>
#include <linux/filter.h>
#include <linux/fs.h>
#include <linux/seccomp.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

static const char socket_path[] = "/dev/socket/mumu_disk_cleanup";
struct reply { int32_t error; uint32_t reserved; uint64_t bytes; };

static int restrict_server(int data_fd) {
#define ALLOW_NR(n) BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_##n, 0, 1), BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_AARCH64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        ALLOW_NR(read), ALLOW_NR(write), ALLOW_NR(close), ALLOW_NR(accept4),
        ALLOW_NR(getsockopt), ALLOW_NR(setsockopt), ALLOW_NR(syncfs),
        ALLOW_NR(rt_sigreturn), ALLOW_NR(exit), ALLOW_NR(exit_group),
        ALLOW_NR(restart_syscall), ALLOW_NR(futex),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_ioctl, 0, 5),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (unsigned)data_fd, 0, 3),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[1])),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, FITRIM, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
    };
#undef ALLOW_NR
    struct sock_fprog program = { .len = sizeof(filter) / sizeof(filter[0]), .filter = filter };
    return prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program);
}

static int transfer(int fd, void *buffer, size_t length, int writing) {
    char *p = buffer;
    while (length) {
        ssize_t n = writing ? write(fd, p, length) : read(fd, p, length);
        if (n < 0 && errno == EINTR) continue;
        if (n == 0) errno = ECONNRESET;
        if (n <= 0) return -1;
        p += n;
        length -= n;
    }
    return 0;
}

static int listen_socket(void) {
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    struct sockaddr_un address = { .sun_family = AF_UNIX };
    memcpy(address.sun_path, socket_path, sizeof(socket_path));
    /* Parent is root-owned; only init starts the singleton service. */
    unlink(socket_path);
    if (bind(fd, (struct sockaddr *)&address, sizeof(address)) ||
        chown(socket_path, 0, 1000) || chmod(socket_path, 0660) || listen(fd, 4)) goto fail;
    return fd;
fail:
    close(fd);
    return -1;
}

static int server(void) {
    if (getuid() != 0) { errno = EPERM; return -1; }
    int data = open("/data", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (data < 0) return -1;
    int listener = listen_socket();
    if (listener < 0) return -1;
    /* Keep only FITRIM's capability. No later exec, path open, mount, or fork is
     * possible after the syscall filter is installed. */
    for (int cap = 0; cap <= CAP_LAST_CAP; cap++)
        if (prctl(PR_CAPBSET_READ, cap, 0, 0, 0) < 0 && errno == EINVAL) break;
        else if (cap != CAP_SYS_ADMIN && prctl(PR_CAPBSET_DROP, cap, 0, 0, 0)) return -1;
    if (prctl(PR_SET_KEEPCAPS, 1) || setgroups(0, NULL) || setgid(1000) || setuid(1000)) return -1;
    struct __user_cap_header_struct h = { .version = _LINUX_CAPABILITY_VERSION_3 };
    struct __user_cap_data_struct caps[2] = {{0}};
    caps[CAP_SYS_ADMIN / 32].effective = caps[CAP_SYS_ADMIN / 32].permitted = 1U << (CAP_SYS_ADMIN % 32);
    if (syscall(__NR_capset, &h, caps) || prctl(PR_SET_DUMPABLE, 0) ||
        prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) || restrict_server(data)) return -1;
    for (;;) {
        int client = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
        if (client < 0) { if (errno == EINTR) continue; return -1; }
        struct timeval timeout = { .tv_sec = 5 };
        setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
        struct ucred peer;
        socklen_t size = sizeof(peer);
        char context[128] = {0};
        socklen_t context_size = sizeof(context);
        char command = 0;
        struct reply reply = { .error = EPERM };
        if (!getsockopt(client, SOL_SOCKET, SO_PEERCRED, &peer, &size) && peer.uid == 1000 &&
            !getsockopt(client, SOL_SOCKET, SO_PEERSEC, context, &context_size) &&
            context_size < sizeof(context) && !strcmp(context, "u:r:system_app:s0") &&
            !transfer(client, &command, 1, 0) && command == 'T') {
            struct fstrim_range range = { .len = UINT64_MAX };
            reply.error = ioctl(data, FITRIM, &range) ? errno : 0;
            reply.bytes = range.len;
            if (!reply.error && syncfs(data)) reply.error = errno;
        }
        transfer(client, &reply, sizeof(reply), 1);
        close(client);
    }
}

int main(int argc, char **argv) {
    /* A disconnected caller must not terminate the maintenance service. */
    signal(SIGPIPE, SIG_IGN);
    int result = -1;
    errno = EINVAL;
    if (argc == 2 && !strcmp(argv[1], "server")) result = server();
    if (result) { perror("MuMu Disk Cleanup failed"); return 1; }
    return 0;
}
