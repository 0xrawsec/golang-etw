package etw

import (
	"sync"

	"github.com/0xrawsec/golang-utils/datastructs"
)

type EventFilter struct {
	sync.RWMutex
	m map[string]*datastructs.Set
}

func NewEventFilter() *EventFilter {
	return &EventFilter{m: make(map[string]*datastructs.Set)}
}

func (f *EventFilter) FilterIn(provider string, eventIds []uint16) {
	f.Lock()
	defer f.Unlock()
	s := datastructs.ToInterfaceSlice(eventIds)
	if _, ok := f.m[provider]; ok {
		f.m[provider].Add(s...)
	} else {
		f.m[provider] = datastructs.NewInitSet(datastructs.ToInterfaceSlice(eventIds)...)
	}
}

func (f *EventFilter) Match(e *Event) bool {
	f.RLock()
	defer f.RUnlock()
	// Filter is empty
	if len(f.m) == 0 {
		return true
	}

	if eventids, ok := f.m[e.Event.System.Provider.Guid]; ok {
		if eventids.Len() > 0 {
			return eventids.Contains(e.Event.System.EventID)
		}
		return true
	}

	return false
}
