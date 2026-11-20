#!/bin/bash
# Build test-only libraries and DEX with the existing Android toolchain.
set -eu
repo=$(cd "$(dirname "$0")/../.." && pwd)
bt=$(python3 "$repo/tests/guest/android_sdk.py" build-tools)
api="$(python3 "$repo/tests/guest/android_sdk.py" platform)/android.jar"
out="$repo/out/guest-tests/frida-dex"
mkdir -p "$out/classes"
javac -source 8 -target 8 -bootclasspath "$api" -d "$out/classes" "$repo/tests/guest/FridaChild.java"
"$bt/d8" --lib "$api" --min-api 26 --output "$out" "$out/classes/io/github/kernelsuemulator/frida/FridaChild.class"
ndk=$(python3 "$repo/tests/guest/android_sdk.py" ndk)
case "$(uname -s)" in
  Darwin) host=darwin-x86_64 ;;
  Linux) host=linux-x86_64 ;;
  *) echo 'Build this Android fixture on macOS or Linux.' >&2; exit 1 ;;
esac
mkdir -p "$repo/out/guest-tests/native"
"$ndk/toolchains/llvm/prebuilt/$host/bin/aarch64-linux-android26-clang" \
  -shared -fPIC -O2 -Wall -Wextra "$repo/tests/guest/frida_library.c" \
  -o "$repo/out/guest-tests/native/libfrida_qualification.so"
