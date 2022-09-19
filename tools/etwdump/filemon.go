package main

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"regexp"

	"github.com/0xrawsec/golang-etw/etw"
)

type file struct {
	name  string
	flags struct {
		read  bool
		write bool
	}
}

type process struct {
	pid   uint32
	image string
}

type hashes struct {
	Md5    string
	Sha1   string
	Sha256 string
	Sha512 string
	Error  string
}

func (h *hashes) String() string {
	if h.Error != "" {
		return fmt.Sprintf("MD5=?;SHA1=?;SHA256=?;SHA512=?;ERROR=%s", h.Error)
	}
	return fmt.Sprintf("MD5=%s;SHA1=%s;SHA256=%s;SHA512", h.Md5, h.Sha1, h.Sha256, h.Sha512)
}

const (
	KernelProcessProviderName    = "Microsoft-Windows-Kernel-Process"
	FilemonKernelProcessProvider = KernelProcessProviderName + ":0xff:1,2"
	KernelFileProviderName       = "Microsoft-Windows-Kernel-File"
	FilemonProvider              = KernelFileProviderName + ":0xff:12,14,15,16"
)

var (
	KernelFileProvider    = etw.MustParseProvider(KernelFileProviderName)
	KernelProcessProvider = etw.MustParseProvider(KernelProcessProviderName)

	fileObjectMapping = make(map[string]*file)
	processMapping    = make(map[uint32]*process)
	filemonRegex      = regexp.MustCompile(".*")
)

func getImageName(pid uint32) string {
	if p, ok := processMapping[pid]; ok {
		return p.image
	}
	return "UNKNOWN"
}

func hash(path string) (h *hashes) {
	var fd *os.File
	var err error

	h = &hashes{}
	if fd, err = os.Open(path); err != nil {
		h.Error = err.Error()
		return
	}
	defer fd.Close()

	md5 := md5.New()
	sha1 := sha1.New()
	sha256 := sha256.New()

	buf := [4096]byte{}

	for n, err := fd.Read(buf[:]); err == nil; n, err = fd.Read(buf[:]) {
		md5.Write(buf[:n])
		sha1.Write(buf[:n])
		sha256.Write(buf[:n])
	}

	if err != io.EOF && err != nil {
		h.Error = err.Error()
	}

	h.Md5 = hex.EncodeToString(md5.Sum(nil))
	h.Sha1 = hex.EncodeToString(sha1.Sum(nil))
	h.Sha256 = hex.EncodeToString(sha256.Sum(nil))

	return
}

func filemonEventRecordCB(r *etw.EventRecord) bool {
	// filter out our own events
	return r.EventHeader.ProcessId != uint32(os.Getpid())
}

func filemonPreparedCB(h *etw.EventRecordHelper) (err error) {

	if h.ProviderGUID() == KernelProcessProvider.GUID {
		var image string
		var pid uint64

		switch h.EventID() {
		// Process start
		case 1:
			if image, err = h.GetPropertyString("ImageName"); err == nil {
				if pid, err = h.GetPropertyUint("ProcessID"); err == nil {
					pid32 := uint32(pid)
					processMapping[pid32] = &process{
						pid:   pid32,
						image: image,
					}
				}
			}
		// Process stop
		case 2:
			delete(processMapping, h.EventRec.EventHeader.ProcessId)
		default:
		}
		h.Skip()
	}

	if h.ProviderGUID() != KernelFileProvider.GUID {
		return
	}

	switch h.EventID() {
	case 12:

		if fo, err := h.GetPropertyString("FileObject"); err == nil {
			if fn, err := h.GetPropertyString("FileName"); err == nil {
				if filemonRegex.MatchString(fn) {
					fileObjectMapping[fo] = &file{name: fn}
				}
			}
		}

		// we skip file create events
		h.Skip()

	case 14:

		// skip file close events
		h.Skip()
		if object, err := h.GetPropertyString("FileObject"); err == nil {
			delete(fileObjectMapping, object)
		}

	case 15, 16:
		var f *file
		var object string
		var ok bool

		if object, err = h.GetPropertyString("FileObject"); err != nil {
			h.Skip()
			break
		}

		if f, ok = fileObjectMapping[object]; !ok {
			// we skip events we cannot enrich
			h.Skip()
			break
		}

		if (h.EventID() == 15 && f.flags.read) ||
			(h.EventID() == 16 && f.flags.write) {
			h.Skip()
			break
		}

		h.SetProperty("TargetFileName", f.name)
		h.SetProperty("Image", getImageName(h.EventRec.EventHeader.ProcessId))
		// output event will only show filename
		h.SelectFields("TargetFileName", "Image")
		f.flags.read = (h.EventID() == 15)
		f.flags.write = (h.EventID() == 16)

	default:
		h.Skip()
	}

	return nil
}
