#!/bin/bash
# Local diagnostic APK only; never part of the installed root payload.
set -eu
repo=$(cd "$(dirname "$0")/../.." && pwd)
root="$repo/out/guest-tests/android"
source_dir="$repo/tests/guest/android"
sdk="${ANDROID_SDK_ROOT:-$HOME/Library/Android/sdk}"
bt="$sdk/build-tools/${ANDROID_BUILD_TOOLS:-35.0.0}"
api="$sdk/platforms/${ANDROID_PLATFORM:-android-35}/android.jar"
mkdir -p "$root/classes" "$root/dex"
javac -source 8 -target 8 -bootclasspath "$api" -d "$root/classes" "$source_dir/src/io/github/kernelsuemulator/probe/ProbeActivity.java"
"$bt/d8" --lib "$api" --min-api 26 --output "$root/dex" "$root"/classes/io/github/kernelsuemulator/probe/*.class
"$bt/aapt" package -f -M "$source_dir/AndroidManifest.xml" -I "$api" -F "$root/unsigned.apk"
(cd "$root/dex" && zip -q "$root/unsigned.apk" classes.dex)
"$bt/zipalign" -f 4 "$root/unsigned.apk" "$root/aligned.apk"
if [ ! -f "$root/lab-key.jks" ]; then
    keytool -genkeypair -keystore "$root/lab-key.jks" -storepass android -keypass android -alias lab -dname 'CN=KernelSU Emulator Lab' -keyalg RSA -validity 3650 >/dev/null 2>&1
fi
"$bt/apksigner" sign --ks "$root/lab-key.jks" --ks-pass pass:android --key-pass pass:android --out "$root/probe.apk" "$root/aligned.apk"
echo "$root/probe.apk"
