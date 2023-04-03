#!/bin/bash

bye() {
    echo -e "$1\n"
    echo -n "Press enter to stop/close this window..."
    read
    exit $2
}

# change to script directory
cd $(pwd)

if [ -z "$ANDROID_HOME" ]; then
    echo "Please set ANDROID_HOME to your Android SDK path"
    echo "Example: export ANDROID_HOME=/home/username/Android/Sdk"
    echo "Example: export ANDROID_HOME=C:\Users\username\AppData\Local\Android\Sdk"
    bye "ANDROID_HOME is not set" 1
fi

echo "Create Proxy APK"
./gradlew assembleRelease || bye "Failed to create Proxy APK" 1

echo "Add Fake Signed"
java -jar tool/uber-apk-signer.jar -a app/build/outputs/apk/release/app-release-unsigned.apk

install_to_phone=false
patching_lspatch=false

# 安卓3.3本地服.apk 4124 official
# 原神3.3-代码服-玩仿官服的不要安装.apk work download data

if ($install_to_phone); then
    # file_apk="apk/official/origin.apk"
    file_apk="apk/not_touch/安卓3.3本地服.apk"
    file_final="apk/final/YuukiPS_V2.apk"
    # file_out="apk/out/origin-361-lspatched.apk"
    file_out="apk/out/安卓3.3本地服-361-lspatched.apk"
    file_our="app/build/outputs/apk/release/app-release-aligned-debugSigned.apk"
    file_cn="apk/mod_cn/xfk233.genshinproxy.apk"

    if ($patching_lspatch); then
        echo "Tried Patching Mod APK with Proxy APK"
        # java -jar tool/lspatch.jar $file_apk -m $file_our -m $file_cn -o apk/out -f
        java -jar tool/lspatch.jar $file_apk -m $file_our -o apk/out -f || bye "Failed to patch Mod APK with Proxy APK" 1

        echo "Rename file..."
        mv $file_out $file_final || bye "Failed to rename file" 1
        # adb install -r "C:\Users\Akbar Yahya\Desktop\Projek\YuukiPS\Launcher-Android\app\build\outputs\apk\release\app-release-aligned-debugSigned.apk"
        echo "Trying to install on phone (Final)"
        adb install -r "$(PWD)/$file_final" || bye "Failed to install on phone (Final)" 1
    else
        echo "Trying to install Module on phone"
        adb install -r "$(PWD)/$file_our" || bye "Failed to install Module on phone" 1
    fi
fi

read -p "Press enter to stop/close this window..."
exit 0