#!/bin/sh
set -eu
# Usage: ISO=fortressedge.iso DISK=data.img [CIDATA=cidata.iso] os/qemu.sh
# QEMU_SMP and QEMU_MEM (MiB) size the guest: 1 vCPU and 512 MiB by default.
# TAP puts it on a tap device (os/netns.sh) instead of the user-mode network.
iso=${ISO:?set ISO}
disk=${DISK:?set DISK}
cidata=${CIDATA:-}
accel=${QEMU_ACCEL:-tcg}
http_fwd=${HTTP_FWD:-18080}
https_fwd=${HTTPS_FWD:-18443}
ctl_fwd=${CTL_FWD:-17000}
# GUEST_ADDR is the guest address hostfwd targets. Empty is QEMU's first
# DHCP address (10.0.2.15); set it when network-config pins another one.
guest=${GUEST_ADDR:-}

# The boot CD is on virtio-scsi: SeaBIOS reads the kernel and initramfs
# from an IDE CD about 2s slower. The NoCloud drive stays on IDE, where
# Proxmox puts it.
set -- -accel "$accel" -nographic -smp "${QEMU_SMP:-1}" -m "${QEMU_MEM:-512}" -rtc base=utc \
	-drive "file=${disk},format=raw,if=virtio" \
	-device virtio-scsi-pci,id=scsi0 \
	-drive "id=iso,file=${iso},media=cdrom,readonly=on,if=none" \
	-device scsi-cd,drive=iso,bus=scsi0.0,bootindex=0
if [ -n "$cidata" ]; then
	# id=cidata lets QMP eject it (Proxmox "detach cloud-init drive").
	set -- "$@" -drive "id=cidata,file=${cidata},media=cdrom,readonly=on,if=ide,index=1"
fi
if [ "$accel" = kvm ]; then
	set -- -cpu host "$@"
fi
# No -no-reboot: a policy that changes a boot-time limit reboots the guest.
# QMP, when set, is how a test sends system_powerdown (Proxmox Shutdown).
qmp=${QMP:-}
if [ -n "$qmp" ]; then
	rm -f "$qmp"
	set -- "$@" -qmp "unix:${qmp},server,nowait"
fi
# TAP, a tap device os/netns.sh made, replaces the user-mode network and
# its port forwards: the guest is reached at its own address. vhost-net
# keeps packets in the kernel, one queue per vCPU; a multi-queue tap
# takes no fewer than two.
tap=${TAP:-}
if [ -n "$tap" ]; then
	queues=${QEMU_SMP:-1}
	[ "$queues" -ge 2 ] || queues=2
	vhost=off
	[ -w /dev/vhost-net ] && vhost=on
	exec qemu-system-x86_64 "$@" \
		-netdev "tap,id=n0,ifname=${tap},script=no,downscript=no,vhost=${vhost},queues=${queues}" \
		-device "virtio-net-pci,netdev=n0,mq=on,vectors=$((2 * queues + 2))"
fi
exec qemu-system-x86_64 "$@" \
	-netdev "user,id=n0,hostfwd=tcp::${http_fwd}-${guest}:80,hostfwd=tcp::${https_fwd}-${guest}:443,hostfwd=udp::${https_fwd}-${guest}:443,hostfwd=tcp::${ctl_fwd}-${guest}:7000" \
	-device virtio-net-pci,netdev=n0
