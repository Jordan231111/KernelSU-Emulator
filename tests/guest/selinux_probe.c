#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/capability.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <unistd.h>

static char *report;
static size_t report_length;
static void record(const char *format, ...) {
    va_list args;
    va_start(args, format);
    int n = vsnprintf(report + report_length, 4096 - report_length, format, args);
    va_end(args);
    if (n > 0 && (size_t)n < 4096 - report_length) report_length += n;
}

static int enter_app_zygote(void) {
    const char *ctx = "u:r:app_zygote:s0";
    int fd = open("/proc/self/attr/current", O_WRONLY);
    if (fd < 0 || setgroups(0, NULL) || setgid(19999) || setuid(19999)) return 1;
    if (write(fd, ctx, strlen(ctx)) != (ssize_t)strlen(ctx)) return 2;
    close(fd);
    return 0;
}

static void context_query(const char *label, const char *context) {
    int fd = open("/sys/fs/selinux/context", O_RDWR);
    if (fd < 0) { record("%s open_errno=%d\n", label, errno); return; }
    errno = 0;
    ssize_t count = write(fd, context, strlen(context));
    int error = errno;
    record("%s accepted=%d errno=%d\n", label, count >= 0, error);
    close(fd);
}

int main(int argc, char **argv) {
    if (argc != 3 || (strcmp(argv[1], "root") && strcmp(argv[1], "app"))) return 2;
    /* app_zygote cannot write the root shell's PTY. A mapping made before the
     * identity change carries observations back without adding policy rules.
     * Every SELinux query below is opened AFTER the identity change. */
    int output = open(argv[2], O_RDWR | O_CREAT | O_TRUNC | O_NOFOLLOW, 0600);
    if (output < 0 || ftruncate(output, 4096)) return 3;
    report = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, output, 0);
    if (report == MAP_FAILED) return 3;
    close(output);
    if (!strcmp(argv[1], "app") && enter_app_zygote()) { record("enter_app_zygote errno=%d\n", errno); return 3; }
    struct __user_cap_header_struct header = { .version = _LINUX_CAPABILITY_VERSION_3 };
    struct __user_cap_data_struct caps[2] = {{0}};
    if (syscall(__NR_capget, &header, caps)) { record("capget errno=%d\n", errno); return 4; }
    char context[128] = {0};
    int fd = open("/proc/self/attr/current", O_RDONLY);
    if (fd < 0 || read(fd, context, sizeof(context) - 1) < 0) { record("read_context errno=%d\n", errno); return 5; }
    close(fd);
    record("uid=%u caps=%08x%08x context=%s\n", getuid(), caps[1].effective, caps[0].effective, context);
    if (!strcmp(argv[1], "app") && (getuid() != 19999 || caps[0].effective || caps[1].effective ||
                                    strcmp(context, "u:r:app_zygote:s0"))) return 6;
    uint32_t status[5];
    fd = open("/sys/fs/selinux/status", O_RDONLY);
    if (fd >= 0) {
        if (read(fd, status, sizeof(status)) == sizeof(status))
            record("status version=%u sequence=%u enforcing=%u policyload=%u deny_unknown=%u\n",
                   status[0], status[1], status[2], status[3], status[4]);
        close(fd);
    } else record("status open_errno=%d\n", errno);
    context_query("stock", "u:r:untrusted_app:s0");
    context_query("root_context", "u:r:ksu:s0");
    context_query("nonexistent", "u:r:ksu_emulator_nonexistent:s0");
    char buffer[256] = {0};
    fd = open("/sys/fs/selinux/class/binder/index", O_RDONLY);
    if (fd < 0 || read(fd, buffer, sizeof(buffer) - 1) <= 0) return 7;
    close(fd);
    int binder = atoi(buffer);
    if (binder <= 0) return 8;
    snprintf(buffer, sizeof(buffer), "u:r:untrusted_app:s0 u:r:ksu:s0 %d", binder);
    fd = open("/sys/fs/selinux/access", O_RDWR);
    if (fd < 0) { record("access open_errno=%d\n", errno); return 9; }
    if (write(fd, buffer, strlen(buffer)) < 0) { record("access write_errno=%d\n", errno); close(fd); return 10; }
    memset(buffer, 0, sizeof(buffer));
    if (read(fd, buffer, sizeof(buffer) - 1) < 0) { close(fd); return 11; }
    close(fd);
    record("access response=%s\n", buffer);
    return 0;
}
