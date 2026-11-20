/* SPDX-License-Identifier: MIT */
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

/* Only the harness's unique app-cache marker is written. The injector unloads
 * this diagnostic library as soon as its entrypoint returns. */
__attribute__((visibility("default")))
void frida_qualification_entry(const char *path, int *stay_resident, void *state) {
    (void)state;
    *stay_resident = 0;
    if (strncmp(path, "/data/user/0/", 13) && strncmp(path, "/data/data/", 11)) return;
    if (!strstr(path, "/cache/ksu-frida-injection-")) return;
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0) return;
    static const char result[] = "frida-injection-qualified\n";
    write(fd, result, sizeof(result) - 1);
    close(fd);
}
