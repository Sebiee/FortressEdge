package main

import (
	"github.com/spf13/cobra"

	"github.com/Sebiee/fortressedge/internal/bootimg"
	"github.com/Sebiee/fortressedge/internal/operator"
)

func newInitramfs() *cobra.Command {
	var out, bin, caFile, modules string
	cmd := &cobra.Command{
		Use:   "initramfs",
		Short: "Write the gzip cpio initramfs",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			return bootimg.WriteInitramfs(out, bin, caFile, modules)
		},
	}
	cmd.Flags().StringVarP(&out, "output", "o", "initramfs.cpio.gz", "output path")
	cmd.Flags().StringVar(&bin, "bin", "", "fortressedge binary, installed as /init")
	cmd.Flags().StringVar(&caFile, "ca-bundle", "", "ca-certificates.crt")
	cmd.Flags().StringVar(&modules, "modules", "", "directory of *.ko or *.ko.gz (optional)")
	_ = cmd.MarkFlagRequired("bin")
	_ = cmd.MarkFlagRequired("ca-bundle")
	return cmd
}

func newISO() *cobra.Command {
	var out, kernel, initrd, isolinux, ldlinux string
	cmd := &cobra.Command{
		Use:   "iso",
		Short: "Write the BIOS boot ISO",
		Long: `El Torito BIOS image for a CD or a VM. It is not a hybrid USB image.
Every date in it is $SOURCE_DATE_EPOCH (seconds since 1970) when set, so
a build is reproducible, and now otherwise.`,
		Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			at, err := bootimg.SourceDateEpoch()
			if err != nil {
				return err
			}
			return bootimg.WriteISO(out, kernel, initrd, isolinux, ldlinux, at)
		},
	}
	cmd.Flags().StringVarP(&out, "output", "o", "fortressedge.iso", "output path")
	cmd.Flags().StringVar(&kernel, "kernel", "", "vmlinuz")
	cmd.Flags().StringVar(&initrd, "initramfs", "", "initramfs.cpio.gz")
	cmd.Flags().StringVar(&isolinux, "isolinux", "/usr/lib/ISOLINUX/isolinux.bin", "isolinux.bin")
	cmd.Flags().StringVar(&ldlinux, "ldlinux", "/usr/lib/syslinux/modules/bios/ldlinux.c32", "ldlinux.c32")
	_ = cmd.MarkFlagRequired("kernel")
	_ = cmd.MarkFlagRequired("initramfs")
	return cmd
}

func newBake() *cobra.Command {
	var out, edge string
	cmd := &cobra.Command{
		Use:   "bake <fortressedge.iso>",
		Short: "Copy a release ISO with fortress.yml baked in",
		Long: `Writes a copy of the release ISO whose initramfs holds fortress.yml: the
ACME server and its CA, the client CA, NTP, and how the edge runs. None
of it is secret, so the ISO can be published as a build artifact. One
ISO serves every edge that shares those settings.

Each machine boots it with a NoCloud (cloud-init) drive that gives its
fqdn in user-data and its address in network-config: what Proxmox,
libvirt, and cloud platforms write from their own settings. The policy
(block, exempt, limits) is applied later: fortressctl apply.`,
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return operator.Bake(out, args[0], edge)
		},
	}
	cmd.Flags().StringVarP(&out, "output", "o", "fortressedge-baked.iso", "output path")
	cmd.Flags().StringVarP(&edge, "config", "c", "fortress.yml", "fortress.yml, with client_ca")
	return cmd
}
