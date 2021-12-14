//go:build windows
// +build windows

package etw

import (
	"fmt"
	"strconv"
	"strings"
	"unsafe"
)

var (
	providers ProviderMap

	DefaultProvider = Provider{EnableLevel: 0xff}
)

type ProviderMap map[string]*Provider

type Provider struct {
	GUID            string
	Name            string
	EnableLevel     uint8
	MatchAnyKeyword uint64
	MatchAllKeyword uint64
}

// ProviderFromString parses a string and returns a provider.
// The returned provider is initialized from DefaultProvider.
// Format (Name|GUID):EnableLevel:MatchAnyKeyword:MatchAllKeyword
func ProviderFromString(s string) (p Provider, err error) {
	var u uint64

	split := strings.Split(s, ":")
	for i := 0; i < len(split); i++ {
		chunk := split[i]
		switch i {
		case 0:
			p = ResolveProvider(chunk)
			if p.IsZero() {
				err = fmt.Errorf("Provider not found: %s", chunk)
				return
			}
		case 1:
			if chunk == "" {
				break
			}
			if u, err = strconv.ParseUint(chunk, 0, 8); err != nil {
				return
			} else {
				p.EnableLevel = uint8(u)
			}
		case 2:
			if chunk == "" {
				break
			}
			if u, err = strconv.ParseUint(chunk, 0, 64); err != nil {
				return
			} else {
				p.MatchAnyKeyword = u
			}
		case 3:
			if chunk == "" {
				break
			}
			if u, err = strconv.ParseUint(chunk, 0, 64); err != nil {
				return
			} else {
				p.MatchAllKeyword = u
			}
		default:
			return
		}
	}
	return
}

// IsZero returns true if the provider is empty
func (p *Provider) IsZero() bool {
	return p.GUID == ""
}

// EnumerateProviders returns a ProviderMap containing available providers
// keys are both provider's GUIDs and provider's names
func EnumerateProviders() (m ProviderMap) {
	var buf *ProviderEnumerationInfo
	size := uint32(1)
	for {
		tmp := make([]byte, size)
		buf = (*ProviderEnumerationInfo)(unsafe.Pointer(&tmp[0]))
		if err := TdhEnumerateProviders(buf, &size); err != ERROR_INSUFFICIENT_BUFFER {
			break
		}
	}
	m = make(ProviderMap)
	startProvEnumInfo := uintptr(unsafe.Pointer(buf))
	it := uintptr(unsafe.Pointer(&buf.TraceProviderInfoArray[0]))
	for i := uintptr(0); i < uintptr(buf.NumberOfProviders); i++ {
		ptpi := (*TraceProviderInfo)(unsafe.Pointer(it + i*unsafe.Sizeof(buf.TraceProviderInfoArray[0])))
		guid := ptpi.ProviderGuid.String()
		name := UTF16AtOffsetToString(startProvEnumInfo, uintptr(ptpi.ProviderNameOffset))
		// We use a default provider here
		p := DefaultProvider
		p.GUID = guid
		p.Name = name
		m[name] = &p
		m[guid] = &p
	}
	return
}

// ResolveProvider return a Provider structure given a GUID or
// a provider name as input
func ResolveProvider(s string) (p Provider) {

	if providers == nil {
		providers = EnumerateProviders()
	}

	if g, err := GUIDFromString(s); err == nil {
		s = g.String()
	}

	if prov, ok := providers[s]; ok {
		// search provider by name
		return *prov
	}

	return
}
