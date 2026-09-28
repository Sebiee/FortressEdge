#!/bin/sh
set -eu
# alpine 3.24.1 linux-virt kernel + ca bundle + virtio/ext4 modules -> $1 (default out/alpine)
ver=3.24.1
out=${1:-out/alpine}
if [ -f "$out/.ver" ] && [ "$(cat "$out/.ver")" = "$ver" ] && [ -f "$out/vmlinuz-virt" ] && [ -f "$out/modules/button.ko.gz" ]; then
	echo "$out/vmlinuz-virt"
	echo "$out/ca-certificates.crt"
	exit 0
fi
mkdir -p "$out/modules"
docker run --rm -v "$(cd "$out" && pwd):/out" "alpine:${ver}" sh -c '
	apk add --no-cache linux-virt ca-certificates >/dev/null
	install -m 0644 /boot/vmlinuz-virt /out/vmlinuz-virt
	install -m 0644 /etc/ssl/certs/ca-certificates.crt /out/ca-certificates.crt
	ver=$(ls /lib/modules)
	copy() { install -m 0644 "$1" "/out/modules/$2"; }
	copy /lib/modules/$ver/kernel/lib/crc/crc16.ko.gz crc16.ko.gz
	copy /lib/modules/$ver/kernel/fs/jbd2/jbd2.ko.gz jbd2.ko.gz
	copy /lib/modules/$ver/kernel/fs/mbcache.ko.gz mbcache.ko.gz
	copy /lib/modules/$ver/kernel/fs/ext4/ext4.ko.gz ext4.ko.gz
	copy /lib/modules/$ver/kernel/net/core/failover.ko.gz failover.ko.gz
	copy /lib/modules/$ver/kernel/drivers/net/net_failover.ko.gz net_failover.ko.gz
	copy /lib/modules/$ver/kernel/drivers/block/virtio_blk.ko.gz virtio_blk.ko.gz
	copy /lib/modules/$ver/kernel/drivers/scsi/virtio_scsi.ko.gz virtio_scsi.ko.gz
	copy /lib/modules/$ver/kernel/drivers/scsi/sd_mod.ko.gz sd_mod.ko.gz
	copy /lib/modules/$ver/kernel/drivers/net/virtio_net.ko.gz virtio_net.ko.gz
	copy /lib/modules/$ver/kernel/fs/nls/nls_cp437.ko.gz nls_cp437.ko.gz
	copy /lib/modules/$ver/kernel/fs/nls/nls_iso8859-1.ko.gz nls_iso8859-1.ko.gz
	copy /lib/modules/$ver/kernel/fs/fat/fat.ko.gz fat.ko.gz
	copy /lib/modules/$ver/kernel/fs/fat/vfat.ko.gz vfat.ko.gz
	copy /lib/modules/$ver/kernel/drivers/cdrom/cdrom.ko.gz cdrom.ko.gz
	copy /lib/modules/$ver/kernel/drivers/scsi/sr_mod.ko.gz sr_mod.ko.gz
	copy /lib/modules/$ver/kernel/fs/isofs/isofs.ko.gz isofs.ko.gz
	copy /lib/modules/$ver/kernel/drivers/input/evdev.ko.gz evdev.ko.gz
	copy /lib/modules/$ver/kernel/drivers/acpi/button.ko.gz button.ko.gz
'
printf '%s\n' "$ver" >"$out/.ver"
echo "$out/vmlinuz-virt"
echo "$out/ca-certificates.crt"
