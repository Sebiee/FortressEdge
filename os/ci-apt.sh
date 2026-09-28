#!/bin/sh
# Install the packages the system tests need. Downloaded .debs stay in
# .apt-cache so a later run can reuse them. apt still installs, which is
# what puts isolinux.bin on disk; a cache of loose files does not.
set -eu
cd "$(dirname "$0")/.."
mkdir -p .apt-cache
sudo tee /etc/apt/apt.conf.d/99-ci-cache >/dev/null <<EOF
Dir::Cache::Archives "$(pwd)/.apt-cache";
EOF
sudo apt-get update
sudo apt-get install -y --no-install-recommends qemu-system-x86 isolinux syslinux-common
test -f /usr/lib/ISOLINUX/isolinux.bin
test -f /usr/lib/syslinux/modules/bios/ldlinux.c32
rm -rf .apt-cache/partial
rm -f .apt-cache/lock
sudo chown -R "$(id -u):$(id -g)" .apt-cache
