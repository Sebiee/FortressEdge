package bootimg

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"
)

// An ISO 9660 image is sectors of 2048 bytes. The primary volume
// descriptor is sector 16; its dates are 17-byte decimal strings, and every
// directory record carries a 7-byte date and, with Rock Ridge, the file's
// owner, link count, and times.
const (
	sector      = 2048
	pvdSector   = 16
	pvdRoot     = 156 // the root directory's record
	pvdCreation = 813 // then modification, expiration, effective, 17 bytes apart
)

// VolumeTime is when the ISO at path says it was made: its primary volume
// descriptor's modification date. Bake stamps its copy with it, so a
// release baked with the same fortress.yml gives the same bytes.
func VolumeTime(path string) (time.Time, error) {
	f, err := os.Open(path)
	if err != nil {
		return time.Time{}, err
	}
	defer f.Close()
	pvd := make([]byte, sector)
	if _, err := f.ReadAt(pvd, pvdSector*sector); err != nil {
		return time.Time{}, fmt.Errorf("%s: %w", path, err)
	}
	if pvd[0] != 1 || string(pvd[1:6]) != "CD001" {
		return time.Time{}, fmt.Errorf("%s: no ISO 9660 primary volume descriptor", path)
	}
	return parseDecDate(pvd[pvdCreation+17 : pvdCreation+34])
}

// SourceDateEpoch is $SOURCE_DATE_EPOCH, the reproducible-builds way to
// fix the time a build writes, or now when it is not set.
func SourceDateEpoch() (time.Time, error) {
	s := os.Getenv("SOURCE_DATE_EPOCH")
	if s == "" {
		return time.Now().UTC().Truncate(time.Second), nil
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < 0 {
		return time.Time{}, fmt.Errorf("SOURCE_DATE_EPOCH %q: want seconds since 1970", s)
	}
	return time.Unix(n, 0).UTC(), nil
}

// stamp rewrites what the image at path took from the clock and from the
// files it was made of, so the same files give the same bytes on any
// machine and OS: every date becomes at, every owner root, every mode 0644
// for a file and 0755 for a directory (Windows keeps no such bits, and a
// umask changes them), and every link count what the image itself holds
// (the file system the files were staged on counts directories its own
// way).
func stamp(path string, at time.Time) error {
	img, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if len(img) < (pvdSector+1)*sector {
		return errors.New("stamp: image too short")
	}
	pvd := img[pvdSector*sector:]
	if pvd[0] != 1 || string(pvd[1:6]) != "CD001" {
		return errors.New("stamp: no ISO 9660 primary volume descriptor")
	}
	at = at.UTC().Truncate(time.Second)
	for i := range 4 {
		copy(pvd[pvdCreation+17*i:], decDate(at))
	}
	root := pvd[pvdRoot : pvdRoot+34]
	s := stamper{img: img, at: at, subdirs: map[uint32]uint32{}}
	if err := s.count(root, 0); err != nil {
		return err
	}
	if err := s.record(root); err != nil {
		return err
	}
	if err := s.walk(root, 0); err != nil {
		return err
	}
	return os.WriteFile(path, img, 0o644)
}

type stamper struct {
	img     []byte
	at      time.Time
	subdirs map[uint32]uint32 // directory extent to its number of subdirectories
}

// entries calls fn for each record in the directory rec names. A record
// never crosses a sector; a zero length pads to the next one.
func (s *stamper) entries(rec []byte, fn func(r []byte) error) error {
	start := int(binary.LittleEndian.Uint32(rec[2:6])) * sector
	end := start + int(binary.LittleEndian.Uint32(rec[10:14]))
	if start < 0 || end > len(s.img) || end < start {
		return fmt.Errorf("stamp: directory at %d outside the image", start)
	}
	for off := start; off < end; {
		n := int(s.img[off])
		if n == 0 {
			off = (off/sector + 1) * sector
			continue
		}
		if n < 34 || off+n > end {
			return fmt.Errorf("stamp: bad directory record at %d", off)
		}
		if err := fn(s.img[off : off+n]); err != nil {
			return err
		}
		off += n
	}
	return nil
}

// self reports whether r is a directory's "." or ".." record.
func self(r []byte) bool { return r[32] == 1 && r[33] <= 1 }

func isDir(r []byte) bool { return r[25]&2 != 0 }

func (s *stamper) count(dir []byte, depth int) error {
	if depth > 16 {
		return errors.New("stamp: directories nested too deep")
	}
	ext := binary.LittleEndian.Uint32(dir[2:6])
	if _, seen := s.subdirs[ext]; seen {
		return nil
	}
	s.subdirs[ext] = 0
	return s.entries(dir, func(r []byte) error {
		if self(r) || !isDir(r) {
			return nil
		}
		s.subdirs[ext]++
		return s.count(r, depth+1)
	})
}

func (s *stamper) walk(dir []byte, depth int) error {
	return s.entries(dir, func(r []byte) error {
		if err := s.record(r); err != nil {
			return err
		}
		if self(r) || !isDir(r) || depth > 16 {
			return nil
		}
		return s.walk(r, depth+1)
	})
}

// record stamps one directory record: its date, and its Rock Ridge
// mode, owner, link count, and times.
func (s *stamper) record(r []byte) error {
	copy(r[18:25], shortDate(s.at))
	px := posix{mode: 0o100644, nlink: 1}
	if isDir(r) {
		px = posix{mode: 0o40755, nlink: 2 + s.subdirs[binary.LittleEndian.Uint32(r[2:6])]}
	}
	su := 33 + int(r[32])
	if r[32]%2 == 0 {
		su++ // padding after an even-length name
	}
	if su > len(r) {
		return nil
	}
	return s.susp(r[su:], px, 0)
}

// posix is what a Rock Ridge PX entry says of a file.
type posix struct{ mode, nlink uint32 }

// susp stamps the System Use entries in area, following a continuation
// area (CE) when there is one.
func (s *stamper) susp(area []byte, px posix, depth int) error {
	for len(area) >= 4 {
		n := int(area[2])
		if n < 4 || n > len(area) {
			return nil
		}
		e := area[:n]
		switch string(e[0:2]) {
		case "PX":
			if n >= 36 {
				putBoth(e[4:12], px.mode)
				putBoth(e[12:20], px.nlink)
				putBoth(e[20:28], 0) // uid
				putBoth(e[28:36], 0) // gid
			}
		case "TF":
			size := 7
			if e[4]&0x80 != 0 {
				size = 17
			}
			for off := 5; off+size <= n; off += size {
				if size == 7 {
					copy(e[off:], shortDate(s.at))
				} else {
					copy(e[off:], decDate(s.at))
				}
			}
		case "CE":
			if n >= 28 && depth < 8 {
				start := int(binary.LittleEndian.Uint32(e[4:8]))*sector + int(binary.LittleEndian.Uint32(e[12:16]))
				end := start + int(binary.LittleEndian.Uint32(e[20:24]))
				if start < 0 || end > len(s.img) || end < start {
					return errors.New("stamp: continuation area outside the image")
				}
				if err := s.susp(s.img[start:end], px, depth+1); err != nil {
					return err
				}
			}
		case "ST":
			return nil
		}
		area = area[n:]
	}
	return nil
}

// putBoth writes v little-endian, then big-endian, as ISO 9660 does.
func putBoth(b []byte, v uint32) {
	binary.LittleEndian.PutUint32(b[0:4], v)
	binary.BigEndian.PutUint32(b[4:8], v)
}

// shortDate is a directory record's date: years since 1900, month, day,
// hour, minute, second, and the offset from UTC in 15 minutes.
func shortDate(t time.Time) []byte {
	return []byte{byte(t.Year() - 1900), byte(t.Month()), byte(t.Day()), byte(t.Hour()), byte(t.Minute()), byte(t.Second()), 0}
}

// decDate is a volume descriptor's date: YYYYMMDDHHMMSS, hundredths, and
// the offset from UTC in 15 minutes.
func decDate(t time.Time) []byte {
	return append([]byte(t.Format("20060102150405")+"00"), 0)
}

func parseDecDate(b []byte) (time.Time, error) {
	t, err := time.Parse("20060102150405", string(b[:14]))
	if err != nil {
		return time.Time{}, fmt.Errorf("volume date %q: %w", b[:16], err)
	}
	return t.Add(-time.Duration(int8(b[16])) * 15 * time.Minute), nil
}
