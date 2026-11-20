FROM ubuntu:22.04@sha256:252bffe20cd96f4eca79e59b95ac87d05021ab22fcf57f621f9e244645c4eac7
RUN apt-get update && task_cross_package='' \
    && if [ "$(dpkg --print-architecture)" != arm64 ]; then task_cross_package='gcc-9-aarch64-linux-gnu libc6-dev-arm64-cross'; fi \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    build-essential gcc-9 $task_cross_package binutils-aarch64-linux-gnu \
    clang lld flex bison bc libssl-dev libelf-dev python3 git patch ca-certificates e2fsprogs \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
