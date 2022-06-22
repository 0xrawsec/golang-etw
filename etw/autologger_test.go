//go:build windows
// +build windows

package etw

import (
	"testing"

	"github.com/0xrawsec/toast"
)

const (
	kernelFileProvider = "Microsoft-Windows-Kernel-File:0xff"
)

func TestAutologger(t *testing.T) {
	t.Parallel()

	tt := toast.FromT(t)

	guid, err := UUID()
	tt.CheckErr(err)

	a := AutoLogger{
		Name:        "AutologgerTest",
		Guid:        guid,
		LogFileMode: 0x8001c0,
		BufferSize:  64,
		ClockType:   2,
	}

	defer a.Delete()

	tt.CheckErr(a.Create())
	provider, err := ParseProvider(kernelFileProvider)
	tt.CheckErr(err)
	tt.CheckErr(a.EnableProvider(provider))
	tt.Assert(a.Exists())
}
