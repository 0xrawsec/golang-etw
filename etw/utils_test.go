//go:build windows
// +build windows

package etw

import (
	"syscall"
	"testing"
	"unsafe"

	"github.com/0xrawsec/toast"
)

func TestUtils(t *testing.T) {

	tt := toast.FromT(t)

	s := "this is a utf16 string"
	sutf16, err := syscall.UTF16PtrFromString(s)
	tt.CheckErr(err)

	tt.Assert(UTF16PtrToString(sutf16) == s)
	tt.Assert(Wcslen(sutf16) == uint64(len(s)))

	// we have to double the length because we are in utf16
	butf16 := CopyData(uintptr(unsafe.Pointer(sutf16)), len(s)*2)

	tt.Assert(len(butf16) == len(s)*2)
	tt.Assert(UTF16BytesToString(butf16) == s)

	uuid, err := UUID()
	tt.CheckErr(err)
	t.Log(uuid)
}
