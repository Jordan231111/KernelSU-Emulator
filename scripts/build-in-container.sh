#!/bin/bash
set -euo pipefail
profile=${1:?profile required}
case "$profile" in mumu-pro-1.9.2-arm64) ;; *) echo 'Unknown build profile' >&2; exit 2;; esac
cd /build/kernel
cp "/src/profiles/$profile/kernel.config" .config
patch --batch --fuzz=0 -p1 < /src/patches/mumu-task-layout.patch
patch --batch --fuzz=0 -d /build/kernelsu -p1 < /src/patches/kernelsu-next-mumu.patch
scripts/config --set-str LOCALVERSION '-android-arm64-gedae1315d023' --disable LOCALVERSION_AUTO
export KBUILD_BUILD_USER=ksu-emulator KBUILD_BUILD_HOST=reproducible
export KBUILD_BUILD_TIMESTAMP='2026-10-15 00:00:00 UTC'
make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- CC=aarch64-linux-gnu-gcc-9 HOSTCC=gcc-9 \
    olddefconfig modules_prepare -j4
make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- CC=aarch64-linux-gnu-gcc-9 HOSTCC=gcc-9 \
    security/selinux/ -j4
make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- CC=clang HOSTCC=gcc-9 \
    M=/build/kernelsu/kernel CONFIG_KSU=m CONFIG_KSU_DEBUG=n CONFIG_KSU_SYSCALL_TABLE_HOOK=y \
    KSU_VERSION_OVERRIDE=33355 KSU_VERSION_TAG_OVERRIDE=v3.4.2 \
    KCFLAGS='-g -std=gnu99' -j4 modules
cp /build/kernelsu/kernel/kernelsu.ko /out/kernelsu.ko
aarch64-linux-gnu-strip --strip-debug /out/kernelsu.ko
aarch64-linux-gnu-gcc-9 -static -O2 -Wall -Wextra -Werror /src/native/ksu_probe.c -o /out/ksu-probe
printf '%s\n' 'Module and verification probe built successfully.'
