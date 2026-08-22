#!/usr/bin/env bash
set -euo pipefail

# Determine repository root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$SCRIPT_DIR"

cd "$REPO_ROOT"

BUILD_TYPE="release"
GRADLE_TASK="assembleRelease"
AUTO_INSTALL=true

while [[ $# -gt 0 ]]; do
    case "$1" in
        --debug)
            BUILD_TYPE="debug"
            GRADLE_TASK="assembleDebug"
            shift
            ;;
        --release)
            BUILD_TYPE="release"
            GRADLE_TASK="assembleRelease"
            shift
            ;;
        --no-install)
            AUTO_INSTALL=false
            shift
            ;;
        -h|--help)
            echo "Usage: ./build_manager.sh [--debug | --release] [--no-install]"
            echo "Builds ksud binaries, KernelSU-Next Manager APK (signed), updates LKM cert hash, and installs on ADB device."
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: ./build_manager.sh [--debug | --release] [--no-install]"
            exit 1
            ;;
    esac
done

echo "===> Setting up JAVA_HOME..."
if [[ -z "${JAVA_HOME:-}" ]] || [[ ! -d "${JAVA_HOME}" ]]; then
    for candidate in /usr/lib/jvm/java-21-openjdk-amd64 /usr/lib/jvm/java-17-openjdk-amd64 /usr/lib/jvm/default-java; do
        if [[ -d "$candidate" ]]; then
            export JAVA_HOME="$candidate"
            break
        fi
    done
fi

if [[ -z "${JAVA_HOME:-}" ]] || [[ ! -d "${JAVA_HOME}" ]]; then
    if command -v java >/dev/null 2>&1; then
        export JAVA_HOME="$(dirname "$(dirname "$(readlink -f "$(which java)")")")"
    fi
fi

if [[ -z "${JAVA_HOME:-}" ]] || [[ ! -d "${JAVA_HOME}" ]]; then
    echo "Error: JAVA_HOME is not set and no suitable JDK was found."
    exit 1
fi
echo "Using JAVA_HOME: $JAVA_HOME"

echo "===> Building ksud release binary (arm64-v8a, platform 26)..."
cd "$REPO_ROOT/userspace/ksud"
cargo ndk -t arm64-v8a --platform 26 build --release

KSUD_BIN="$REPO_ROOT/userspace/ksud/target/aarch64-linux-android/release/ksud"
if [[ ! -f "$KSUD_BIN" ]]; then
    KSUD_BIN="$REPO_ROOT/target/aarch64-linux-android/release/ksud"
fi

echo "===> Copying ksud binary to manager jniLibs..."
mkdir -p "$REPO_ROOT/manager/app/src/main/jniLibs/arm64-v8a"
cp "$KSUD_BIN" "$REPO_ROOT/manager/app/src/main/jniLibs/arm64-v8a/libksud.so"

echo "===> Building & Signing Manager APK ($GRADLE_TASK)..."
rm -rf "$REPO_ROOT/manager/app/build"
cd "$REPO_ROOT/manager"
./gradlew "$GRADLE_TASK" \
    -PKEYSTORE_FILE=app/ksu.keystore \
    -PKEYSTORE_PASSWORD=kernelsu \
    -PKEY_ALIAS=ksu \
    -PKEY_PASSWORD=kernelsu

echo "===> Build completed successfully!"
APK_PATH="$(find "$REPO_ROOT/manager/app/build/outputs/apk/$BUILD_TYPE" -name "*.apk" | head -n 1)"
echo "Signed APK built: $APK_PATH"

echo "===> Updating certificate signature in KernelSU-Next Kbuild..."
python3 "$REPO_ROOT/scripts/extract_apk_cert.py" --update "$APK_PATH"

if [[ "$AUTO_INSTALL" == "true" ]]; then
    if command -v adb >/dev/null 2>&1 && adb get-state >/dev/null 2>&1; then
        echo "===> ADB device detected."
        for PKG in "com.rifsxd.ksunext" "me.weishu.kernelsu" "me.weishu.kernelsu.pr"; do
            if adb shell "pm path $PKG" >/dev/null 2>&1; then
                echo "===> Uninstalling existing $PKG..."
                adb shell "pm uninstall $PKG" || true
            fi
        done
        
        echo "===> Installing new signed Manager APK ($APK_PATH)..."
        adb install -r "$APK_PATH"
        echo "===> Manager installation finished!"
    else
        echo "===> No ADB device detected, skipping automatic installation."
    fi
fi

echo "===> All tasks completed successfully!"
