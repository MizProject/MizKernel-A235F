#!/bin/bash

export ARCH=arm64
export KBUILD_BUILD_USER="@Mizumo_prjkt"
export KBUILD_BUILD_HOST="MizProject (MIZPRJKT)"
mkdir out

OPATH=$PATH
export PATH=$(pwd)/toolchain/clang-r416183b/bin:$(pwd)/toolchain/aarch64-linux-android-4.9-llvm/bin:$OPATH

build_kernel() {
    BUILD_CROSS_COMPILE=$(pwd)/toolchain/aarch64-linux-android-4.9/bin/aarch64-linux-android-
    KERNEL_LLVM_BIN=$(pwd)/toolchain/clang-r416183b/bin/clang
    CLANG_TRIPLE=aarch64-linux-gnu-
    KERNEL_MAKE_ENV="DTC_EXT=$(pwd)/tools/dtc CONFIG_BUILD_ARM64_DT_OVERLAY=y"

    make -j64 -C $(pwd) O=$(pwd)/out $KERNEL_MAKE_ENV ARCH=arm64 CROSS_COMPILE=$BUILD_CROSS_COMPILE REAL_CC=$KERNEL_LLVM_BIN CLANG_TRIPLE=$CLANG_TRIPLE CONFIG_SECTION_MISMATCH_WARN_ONLY=y vendor/a23_eur_open_mizkernel_defconfig
    make -j64 -C $(pwd) O=$(pwd)/out $KERNEL_MAKE_ENV ARCH=arm64 CROSS_COMPILE=$BUILD_CROSS_COMPILE REAL_CC=$KERNEL_LLVM_BIN CLANG_TRIPLE=$CLANG_TRIPLE CONFIG_SECTION_MISMATCH_WARN_ONLY=y
 
    cp out/arch/arm64/boot/Image $(pwd)/arch/arm64/boot/Image
}

submodule_summon() {
    git submodule init
    git submoudule update
}

ksu_symlink() {
     if [ ! -d "KernelSU-Next/kernel" ]; then
        echo "Empty KernelSU-Next/kernel directory, abort as extreme error"
        exit 9
    fi
    ln -sf $(pwd)/KernelSU-Next/kernel $(pwd)/drivers/kernelsu
    if [ $? -ne 0 ]; then
        echo "Failed to create symlink for KernelSU-Next/kernel"
        exit 1
    fi
}

menuconfig_summon() {
    BUILD_CROSS_COMPILE=$(pwd)/toolchain/aarch64-linux-android-4.9/bin/aarch64-linux-android-
    KERNEL_LLVM_BIN=$(pwd)/toolchain/clang-r416183b/bin/clang
    CLANG_TRIPLE=aarch64-linux-gnu-
    KERNEL_MAKE_ENV="DTC_EXT=$(pwd)/tools/dtc CONFIG_BUILD_ARM64_DT_OVERLAY=y"
    make menuconfig
}

case "$1" in
    "build")
        # Use ksu_symlink as always since object files are permanently configured
        # and to avoid future errors relating "missing file or foler"
        ksu_symlink
        if [ "$2" == "-submodule_summon" ]; then
            submodule_summon
        fi
            build_kernel
        ;;
    "menuconfig")
        ksu_symlink
        menuconfig_summon
        ;;
    "submodule_summon")
        submodule_summon
        ;;
    *)
        echo "Usage: $0 {build (-submodule_summon)|menuconfig|submodule_summon}"
        exit 1
        ;;
esac
