FROM ubuntu:22.04@sha256:5ec03bb3441e8b0bf3b4f9cd4629a1ae763010dc3035bb8da3ae6cf026486401
RUN apt-get update && task_cross_package='' \
    && if [ "$(dpkg --print-architecture)" != arm64 ]; then task_cross_package=gcc-9-aarch64-linux-gnu; fi \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    build-essential gcc-9 $task_cross_package binutils-aarch64-linux-gnu \
    clang flex bison bc libssl-dev libelf-dev python3 git patch ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
