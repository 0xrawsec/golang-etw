//go:build windows
// +build windows

package etw

import (
	"testing"

	"github.com/0xrawsec/toast"
)

func hasFlag(flags, flag uint32) bool {
	return flags&flag == flag
}

func TestKernelProviders(t *testing.T) {
	tt := toast.FromT(t)

	for _, p := range KernelProviders {
		tt.Assert(IsKernelProvider(p.Name))
		tt.Assert(IsKernelProvider(p.GUID))

		tt.Assert(GetKernelProviderFlags(p.Name) == p.Flags)
		// some providers have the same GUID so we have to check flags contains p.Flags
		tt.Assert(GetKernelProviderFlags(p.GUID)&p.Flags == p.Flags)
	}

	combinedFlags := GetKernelProviderFlags("ALPC", "ImageLoad")
	tt.Assert(combinedFlags != EVENT_TRACE_FLAG_ALPC)
	tt.Assert(hasFlag(combinedFlags, EVENT_TRACE_FLAG_ALPC))
	tt.Assert(combinedFlags != EVENT_TRACE_FLAG_IMAGE_LOAD)
	tt.Assert(hasFlag(combinedFlags, EVENT_TRACE_FLAG_IMAGE_LOAD))
}
