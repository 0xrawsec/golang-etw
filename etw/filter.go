package etw

import (
	"sync"

	"github.com/0xrawsec/golang-utils/datastructs"
)

type EventFilter interface {
	Match(*Event) bool
	FromProvider(p *Provider)
}

type AllInFilter struct{}

func (f *AllInFilter) Match(*Event) bool {
	return true
}

type BaseFilter struct {
	sync.RWMutex
	m map[string]*datastructs.Set
}

func (f *BaseFilter) FromProvider(p *Provider) {
	f.Lock()
	defer f.Unlock()
	if len(p.Filter) > 0 {
		s := datastructs.ToInterfaceSlice(p.Filter)
		if _, ok := f.m[p.GUID]; ok {
			f.m[p.GUID].Add(s...)
		} else {
			f.m[p.GUID] = datastructs.NewInitSet(s...)
		}
	}
}

func (f *BaseFilter) MatchKey(key string, e *Event) bool {
	f.RLock()
	defer f.RUnlock()

	// map is nil
	if f.m == nil {
		return true
	}

	// Filter is empty
	if len(f.m) == 0 {
		return true
	}

	if eventids, ok := f.m[key]; ok {
		if eventids.Len() > 0 {
			return eventids.Contains(e.System.EventID)
		}
		return true
	}
	// we return true if no filter is found
	return true
}

type ProviderFilter struct {
	BaseFilter
}

func NewProviderFilter() *ProviderFilter {
	f := ProviderFilter{}
	f.m = make(map[string]*datastructs.Set)
	return &f
}

func (f *ProviderFilter) Match(e *Event) bool {
	return f.MatchKey(e.System.Provider.Guid, e)
}

type ChannelFilter struct {
	BaseFilter
}

func NewChannelFilter() *ChannelFilter {
	f := ChannelFilter{}
	f.m = make(map[string]*datastructs.Set)
	return &f
}

func (f *ChannelFilter) Match(e *Event) bool {
	return f.MatchKey(e.System.Channel, e)
}
