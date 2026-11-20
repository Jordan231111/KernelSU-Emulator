/* SPDX-License-Identifier: MIT
 * Freestanding ARM64 client: Android app children inherit a seccomp policy
 * that rejects startup syscalls made by a desktop glibc. No libc, linker, or
 * privilege transition is needed for this fixed system-UID request.
 */
#include <asm/unistd.h>

static const char request[] = "fstrim /data && sync && exit 0 \n  || exit 1\n";
static const struct { unsigned short family; char path[108]; } address =
    { 1, "/dev/socket/mumu_disk_cleanup" };
struct response { int error; unsigned reserved; unsigned long long bytes; };

static long sys6(long nr, long a, long b, long c, long d, long e, long f) {
    register long x8 __asm__("x8") = nr;
    register long x0 __asm__("x0") = a;
    register long x1 __asm__("x1") = b;
    register long x2 __asm__("x2") = c;
    register long x3 __asm__("x3") = d;
    register long x4 __asm__("x4") = e;
    register long x5 __asm__("x5") = f;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5) : "memory", "cc");
    return x0;
}

static void number(int fd, unsigned long long value) {
    char text[24];
    unsigned i = sizeof(text);
    text[--i] = '\n';
    do { text[--i] = '0' + value % 10; value /= 10; } while (value);
    sys6(__NR_write, fd, (long)(text + i), sizeof(text) - i, 0, 0, 0);
}

static long read_all(int fd, char *data, unsigned length) {
    while (length) {
        if (fd == 0) {
            struct { int fd; short events, returned; } pollfd = {0, 1, 0};
            struct { long seconds, nanos; } timeout = {5, 0};
            long n = sys6(__NR_ppoll, (long)&pollfd, 1, (long)&timeout, 0, 8, 0);
            if (n == -4) continue;
            if (n <= 0) return n ? n : -110;
        }
        long n = sys6(__NR_read, fd, (long)data, length, 0, 0, 0);
        if (n == -4) continue;
        if (n <= 0) return n ? n : -104;
        data += n;
        length -= n;
    }
    return 0;
}

static long client(unsigned long argc) {
    if (argc != 1 || sys6(__NR_getuid, 0, 0, 0, 0, 0, 0) != 1000) return -1;
    char text[sizeof(request) - 1];
    long result = read_all(0, text, sizeof(text));
    if (result) return result;
    for (unsigned i = 0; i < sizeof(text); i++) if (text[i] != request[i]) return -22;
    long fd = sys6(__NR_socket, 1, 1 | 02000000, 0, 0, 0, 0);
    if (fd < 0) return fd;
    result = sys6(__NR_connect, fd, (long)&address, sizeof(address), 0, 0, 0);
    if (result) goto done;
    struct { long seconds, micros; } timeout = {90, 0};
    result = sys6(__NR_setsockopt, fd, 1, 20, (long)&timeout, sizeof(timeout), 0);
    if (result) goto done;
    result = sys6(__NR_sendto, fd, (long)"T", 1, 0x4000, 0, 0);
    if (result != 1) { if (result >= 0) result = -5; goto done; }
    struct response response;
    result = read_all(fd, (char *)&response, sizeof(response));
    if (result) goto done;
    result = -response.error;
    if (!result) {
        static const char success[] = "MuMu Disk Cleanup: trimmed bytes=";
        sys6(__NR_write, 1, (long)success, sizeof(success) - 1, 0, 0, 0);
        number(1, response.bytes);
    }
done:
    sys6(__NR_close, fd, 0, 0, 0, 0, 0);
    return result;
}

__attribute__((used, noreturn)) void cleanup_entry(unsigned long *stack) {
    long result = client(stack[0]);
    if (result) {
        static const char failure[] = "MuMu Disk Cleanup failed: errno=";
        sys6(__NR_write, 2, (long)failure, sizeof(failure) - 1, 0, 0, 0);
        number(2, -result);
    }
    sys6(__NR_exit_group, result ? 1 : 0, 0, 0, 0, 0, 0);
    for (;;) {}
}

__attribute__((naked, noreturn)) void _start(void) {
    __asm__ volatile("mov x0, sp\nb cleanup_entry");
}
