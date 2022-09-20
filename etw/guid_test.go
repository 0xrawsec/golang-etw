package etw

import (
	"fmt"
	"strings"
	"testing"

	"github.com/0xrawsec/toast"
)

func TestGUID(t *testing.T) {
	t.Parallel()

	var g *GUID
	var err error

	tt := toast.FromT(t)

	// with curly brackets
	guid := "{45d8cccd-539f-4b72-a8b7-5c683142609a}"
	g, err = ParseGUID(guid)
	tt.CheckErr(err)
	tt.Assert(!g.IsZero())
	tt.Assert(strings.EqualFold(guid, g.String()))

	guid = "54849625-5478-4994-a5ba-3e3b0328c30d"
	g, err = ParseGUID(guid)
	tt.CheckErr(err)
	tt.Assert(!g.IsZero())
	tt.Assert(strings.EqualFold(fmt.Sprintf("{%s}", guid), g.String()))

	guid = "00000000-0000-0000-0000-000000000000"
	g, err = ParseGUID(guid)
	tt.CheckErr(err)
	tt.Assert(g.IsZero())
	tt.Assert(strings.EqualFold(fmt.Sprintf("{%s}", guid), g.String()))
}

func TestGUIDEquality(t *testing.T) {
	t.Parallel()

	tt := toast.FromT(t)
	p := MustParseProvider("Microsoft-Windows-Kernel-File")
	g1 := MustParseGUIDFromString(p.GUID)
	g2 := MustParseGUIDFromString(p.GUID)

	tt.Assert(g1.Equals(g2))

	// testing Data1
	g2.Data1++
	tt.Assert(!g1.Equals(g2))

	// testing Data2
	g2 = MustParseGUIDFromString(p.GUID)
	g2.Data2++
	tt.Assert(!g1.Equals(g2))

	// testing Data3
	g2 = MustParseGUIDFromString(p.GUID)
	g2.Data3++
	tt.Assert(!g1.Equals(g2))

	// testing Data4
	for i := 0; i < 8; i++ {
		g2 = MustParseGUIDFromString(p.GUID)
		g2.Data4[i]++
		tt.Assert(!g1.Equals(g2))
	}
}
