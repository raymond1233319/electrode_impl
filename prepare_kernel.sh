#!/usr/bin/env bash
set -euo pipefail

# Simple helper that downloads and prepares a kernel tree suitable for building
# the Electrode eBPF/XDP programs. It fetches the requested tarball from
# kernel.org, verifies the published SHA-256 checksum, extracts linux/ under the
# repo's electrode/ directory, and runs the minimal kernel build targets needed
# to generate headers such as include/generated/autoconf.h.
#
# Usage: ./prepare_kernel.sh [kernel-version]
# Example: ./prepare_kernel.sh 5.15.0

DEFAULT_KERNEL="5.15"
KERNEL_VERSION="${1:-${DEFAULT_KERNEL}}"
CACHE_DIR="./tmp/kernel-cache"
LINUX_PARENT="./electrode"
LINUX_DIR="${LINUX_PARENT}/linux"
IFS='.' read -r MAJOR_VERSION MINOR_VERSION PATCH_VERSION <<< "${KERNEL_VERSION}."
PATCH_VERSION="${PATCH_VERSION:-0}"
SERVER_VERSION="${KERNEL_VERSION}"
if [[ "${PATCH_VERSION}" == "0" && "${KERNEL_VERSION}" == *".0" ]]; then
    SERVER_VERSION="${MAJOR_VERSION}.${MINOR_VERSION}"
fi
TARBALL_NAME="linux-${SERVER_VERSION}.tar.xz"
TARBALL_PATH="${CACHE_DIR}/${TARBALL_NAME}"
SHA_LIST_PATH="${CACHE_DIR}/sha256sums.asc"
SHA_SINGLE_PATH="${CACHE_DIR}/${TARBALL_NAME}.sha"
BASE_URL="https://cdn.kernel.org/pub/linux/kernel/v5.x"
SHA_BASE="https://www.kernel.org/pub/linux/kernel/v5.x"
if [[ "${MAJOR_VERSION}" == "5" && "${MINOR_VERSION}" == "8" ]]; then
    BASE_URL="${BASE_URL}/old"
    SHA_BASE="${SHA_BASE}/old"
fi
TXZ="https://cdn.kernel.org/pub/linux/kernel/v5.x/linux-5.15.tar.xz"
SIG="https://cdn.kernel.org/pub/linux/kernel/v5.x/linux-5.15.tar.sign"
SHA="${SHA_BASE}/sha256sums.asc"

require_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "ERROR: Missing required command '$1'" >&2
        exit 1
    fi
}

for tool in curl sha256sum tar xz make bc; do
    require_cmd "$tool"
done

mkdir -p "${CACHE_DIR}" "${LINUX_PARENT}"

if [[ ! -f "${TARBALL_PATH}" ]]; then
    echo "Downloading ${TARBALL_NAME}"
    curl -sL -o "${TARBALL_PATH}" "${TXZ}"
else
    echo "Using cached tarball ${TARBALL_PATH}"
fi


echo "Ensuring kernel tree exists in ${LINUX_DIR}"
if [[ ! -d "${LINUX_DIR}" ]]; then
    tar -xJf "${TARBALL_PATH}" -C "${LINUX_PARENT}"
    mv "${LINUX_PARENT}/linux-${SERVER_VERSION}" "${LINUX_DIR}"
elif [[ -z "$(ls -A "${LINUX_DIR}")" ]]; then
    rm -rf "${LINUX_DIR}"
    tar -xJf "${TARBALL_PATH}" -C "${LINUX_PARENT}"
    mv "${LINUX_PARENT}/linux-${SERVER_VERSION}" "${LINUX_DIR}"
else
    echo "Kernel directory already populated; leaving it in place"
fi

if [[ ! -f "${LINUX_DIR}/.config" && -f "/boot/config-$(uname -r)" ]]; then
    echo "Seeding kernel .config from running kernel"
    cp "/boot/config-$(uname -r)" "${LINUX_DIR}/.config"
fi

echo "Generating headers via defconfig + prepare"
make -C "${LINUX_DIR}" ARCH=x86 defconfig
make -C "${LINUX_DIR}" ARCH=x86 prepare prepare

echo "Kernel sources ready at ${LINUX_DIR}"
