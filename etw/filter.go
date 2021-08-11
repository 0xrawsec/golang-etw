package etw

import (
	"sync"

	"github.com/0xrawsec/golang-utils/datastructs"
)

type EventFilter interface {
	Match(*Event) bool
}

type AllInFilter struct{}

func (f *AllInFilter) Match(*Event) bool {
	return true
}

type BaseFilter struct {
	sync.RWMutex
	m map[string]*datastructs.Set
}

func (f *BaseFilter) FilterIn(key string, eventIds []uint16) {
	f.Lock()
	defer f.Unlock()
	s := datastructs.ToInterfaceSlice(eventIds)
	if _, ok := f.m[key]; ok {
		f.m[key].Add(s...)
	} else {
		f.m[key] = datastructs.NewInitSet(datastructs.ToInterfaceSlice(eventIds)...)
	}
}

func (f *BaseFilter) MatchKey(key string, e *Event) bool {
	f.RLock()
	defer f.RUnlock()
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

	return false
}

type ProviderFilter struct {
	BaseFilter
}

func NewEventFilter() *ProviderFilter {
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
