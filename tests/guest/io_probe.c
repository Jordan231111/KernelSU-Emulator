#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <inttypes.h>
#include <linux/capability.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

static int app(void) {
    const char *ctx = "u:r:untrusted_app:s0";
    int f = open("/proc/self/attr/current", O_WRONLY);
    if (f < 0) return 1;
    if (setgroups(0, NULL) || setgid(19999) || setuid(19999)) return 2;
    if (write(f, ctx, strlen(ctx)) < 0) return 3;
    close(f);
    return prctl(PR_SET_DUMPABLE, 1);
}

static int mapping_lines(const char *proc, const char *path) {
    FILE *f = fopen(proc, "r");
    if (!f) return -1;
    char *line = NULL;
    size_t n = 0;
    int found = 0;
    while (getline(&line, &n, f) > 0) if (strstr(line, path)) found++;
    free(line);
    fclose(f);
    return found;
}

int main(int argc, char **argv) {
    if (argc < 3) return 2;
    if (argc > 3 && app()) { perror("drop to app"); return 3; }
    struct __user_cap_header_struct ch = { .version = _LINUX_CAPABILITY_VERSION_3 };
    struct __user_cap_data_struct cd[2] = {{0}};
    syscall(__NR_capget, &ch, cd);
    printf("uid=%u caps=%08x%08x\n", getuid(), cd[1].effective, cd[0].effective);
    if (!strcmp(argv[1], "exec")) {
        fflush(stdout);
        execl(argv[2], argv[2], NULL);
        perror("exec"); return 4;
    }
    int fd = open(argv[2], O_RDONLY);
    if (fd < 0) { printf("open_errno=%d\n", errno); return 5; }
    if (!strcmp(argv[1], "map")) {
        void *p = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, fd, 0);
        if (p == MAP_FAILED) { perror("mmap"); return 6; }
        printf("mapped_byte=%u\n", *(volatile unsigned char *)p);
        printf("map_visible=%d\n", mapping_lines("/proc/self/maps", argv[2]));
        printf("smaps_visible=%d\n", mapping_lines("/proc/self/smaps", argv[2]));
        printf("rollup_read=%d\n", mapping_lines("/proc/self/smaps_rollup", "Rss:"));
        int pm = open("/proc/self/pagemap", O_RDONLY);
        uint64_t entry = UINT64_MAX;
        ssize_t bytes = pm < 0 ? -1 : pread(pm, &entry, 8, ((uintptr_t)p / 4096) * 8);
        printf("pagemap_bytes=%zd entry=%016" PRIx64 "\n", bytes, entry);
        if (pm >= 0) close(pm);
        int mem = open("/proc/self/mem", O_RDONLY);
        unsigned char value = 0;
        errno = 0;
        bytes = mem < 0 ? -1 : pread(mem, &value, 1, (uintptr_t)p);
        printf("mem_bytes=%zd errno=%d\n", bytes, errno);
        if (mem >= 0) close(mem);
        munmap(p, 4096);
    } else {
        char b[128] = {0};
        ssize_t n = read(fd, b, 127);
        printf("read_bytes=%zd content=%s\n", n, b);
        struct stat st;
        if (!fstat(fd, &st)) printf("fd_ino=%lu\n", (unsigned long)st.st_ino);
        char link[80], value[512] = {0};
        snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
        ssize_t count = readlink(link, value, 511);
        if (count >= 0) value[count] = 0;
        printf("fd_path=%s\n", value);
    }
    close(fd);
    return 0;
}
