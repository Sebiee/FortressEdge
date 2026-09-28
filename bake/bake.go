// Package bake makes an edge's ISO as fortressctl bake does, for tools
// outside this repository, such as the Terraform provider: check a
// fortress.yml as the edge would, and bake it into a release ISO. The same
// release and fortress.yml give the same bytes, whichever tool bakes them,
// on any OS, as long as it builds against the same version of this module.
package bake

import (
	"time"

	"github.com/Sebiee/fortressedge/internal/bootimg"
	"github.com/Sebiee/fortressedge/internal/config"
)

// Check reports what is wrong with a fortress.yml, as the edge would.
func Check(fortressYML []byte) error { return config.CheckEdge(fortressYML) }

// WriteISO writes a release ISO as fortressctl iso does: a BIOS boot CD of
// the kernel, the initramfs, and the syslinux files, every date at.
func WriteISO(dest, kernel, initramfs, isolinux, ldlinux string, at time.Time) error {
	return bootimg.WriteISO(dest, kernel, initramfs, isolinux, ldlinux, at)
}

// ISO writes dest: the release ISO at release with fortressYML in its
// initramfs, dated as the release. It refuses a fortress.yml that Check
// refuses.
func ISO(dest, release string, fortressYML []byte) error {
	if err := Check(fortressYML); err != nil {
		return err
	}
	return bootimg.Bake(dest, release, fortressYML)
}
