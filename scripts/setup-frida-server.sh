#!/bin/bash

# This script is used to install frida-server on device which is connected by adb.
#
# arguments list:
#   $1    adb_serial. This will be used as the value of `adb -s` parameter

adb_serial=$1

function adb() {
    if [[ ${adb_serial} -eq "" ]]; then
        command adb $@
    else
        command adb -s ${adb_serial} $@
    fi
}

PARCH=$(adb shell getprop ro.product.cpu.abi)
[[ "${PARCH}" == *"armeabi"* ]] && PARCH="arm"
[[ "${PARCH}" == *"arm64"* ]] && PARCH="arm64"

# exit when piped command fail
set -o pipefail

temp_dir=$(mktemp --directory) || exit $?
cd ${temp_dir}

wget -q -O - https://api.github.com/repos/frida/frida/releases |
    jq '.[0] | .assets[] | select(.browser_download_url | match("server(.*?)android-'${PARCH}'*\\.xz")).browser_download_url' |
    xargs wget -q --show-progress &&
    unxz frida-server* &&
    adb push frida-server* /data/local/tmp/frida-server &&
    cd - && rm -rf ${temp_dir} &&
    adb shell "chmod 755 /data/local/tmp/frida-server" &&
    adb shell "/data/local/tmp/frida-server &"
