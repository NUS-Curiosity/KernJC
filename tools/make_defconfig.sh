#!/bin/bash

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <path_to_kernel_source>"
    exit 1
fi

KERNEL_SRC_DIR="$1"
cd "$KERNEL_SRC_DIR" || { echo "Failed to change to directory $KERNEL_SRC_DIR"; exit 1; }
make clean
rm .config
make defconfig

CONFIGS=(
CONFIG_DEBUG_INFO_DWARF4=y
CONFIG_CONFIGFS_FS=y
CONFIG_SECURITYFS=y
CONFIG_KCOV=y
CONFIG_KASAN=y
CONFIG_KASAN_INLINE=y
CONFIG_KALLSYMS_ALL=y
CONFIG_DEBUG_INFO=y
CONFIG_BINFMT_MISC=y
CONFIG_USER_NS=y
CONFIG_NET_NS=y
CONFIG_E1000=y
CONFIG_E1000E=y
CONFIG_SYSVIPC=y
)

for CONFIG in "${CONFIGS[@]}"; do
    KEY="${CONFIG%=*}"
    VALUE="${CONFIG#*=}"
    if grep -q "^$KEY=" .config; then
        sed -i "s/^$KEY=.*/$KEY=$VALUE/" .config
    else
        echo "$KEY=$VALUE" >> .config
    fi
done

make olddefconfig
