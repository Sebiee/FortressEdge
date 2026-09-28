#!/bin/sh
# Runs a command in a network namespace of its own with a tap device for
# QEMU: TAP (default fortress0), multi-queue, at 10.77.0.1/24. A VM on it
# talks to the host through the kernel, with vhost-net when
# /dev/vhost-net is writable, instead of QEMU's user-mode network.
#
#   os/netns.sh go test ... -args -tap=fortress0
#
# No root: an unprivileged user namespace gives its root CAP_NET_ADMIN
# over the new network namespace. The command reaches nothing outside
# it, so fetch what it needs first. Ubuntu 24.04 lets only AppArmor
# profiles make user namespaces unless
# kernel.apparmor_restrict_unprivileged_userns=0.
set -eu
if [ "${FORTRESS_NETNS:-}" != 1 ]; then
	FORTRESS_NETNS=1 exec unshare --user --map-root-user --net "$0" "$@"
fi
tap=${TAP:-fortress0}
ip link set lo up
ip tuntap add dev "$tap" mode tap multi_queue
ip addr add 10.77.0.1/24 dev "$tap"
ip link set "$tap" up
exec "$@"
