package main

import (
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

const (
	KernelFileProviderName = "Microsoft-Windows-Kernel-File"
	FilemonProvider        = KernelFileProviderName + ":0xff:12,14,15,16"
)

var (
	KernelProvider    = etw.MustParseProvider(KernelFileProviderName)
	fileObjectMapping = make(map[string]*file)
	filemonRegex      = regexp.MustCompile(".*")
)

func filemonPreparedCB(h *etw.EventRecordHelper) (err error) {

	if h.ProviderGUID() != KernelProvider.GUID {
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

		if object, err := h.GetPropertyString("FileObject"); err == nil {
			delete(fileObjectMapping, object)
		}

		// skip file close events
		h.Skip()

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

		h.SetProperty("FileName", f.name)
		// output event will only show filename
		h.SelectFields("FileName")
		f.flags.read = (h.EventID() == 15)
		f.flags.write = (h.EventID() == 16)

	default:
		h.Skip()
	}

	return nil
}
