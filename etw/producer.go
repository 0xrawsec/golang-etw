//go:build windows
// +build windows

package etw

import (
	"syscall"
)

const (
	AllKeywords    = 0xffffffffffffffff
	MaxLevel       = 255
	NtKernelLogger = "NT Kernel Logger"

	//  0x9e814aad, 0x3204, 0x11d2, 0x9a, 0x82, 0x00, 0x60, 0x08, 0xa8, 0x69, 0x39
	SystemTraceControlGuid = "{9E814AAD-3204-11D2-9A82-006008A86939}"
)

type RealTimeSession struct {
	properties    *EventTraceProperties
	sessionHandle syscall.Handle

	TraceName string
	Providers []string
}

func NewRealTimeProducer(name string) (p *RealTimeSession) {
	p = &RealTimeSession{}
	p.properties = NewRealTimeEventTraceSessionProperties(name)
	p.TraceName = name
	p.Providers = make([]string, 0)
	return
}

func NewKernelRealTimeProducer(flags ...uint32) (p *RealTimeSession) {
	p = NewRealTimeProducer(NtKernelLogger)
	p.properties.Wnode.Guid = *MustGUIDFromString(SystemTraceControlGuid)
	for _, flag := range flags {
		p.properties.EnableFlags |= flag
	}
	return
}

func (p *RealTimeSession) Started() bool {
	return p.sessionHandle != 0
}

//func (p *RealTimeSession) EnableProvider(sguid string, level uint8, keywords uint64) (err error) {
func (p *RealTimeSession) EnableProvider(prov Provider) (err error) {
	var guid *GUID

	// If the trace is not started yet we have to start it
	// otherwise we cannot enable provider
	if !p.Started() {
		if err = p.Start(); err != nil {
			return
		}
	}

	if guid, err = GUIDFromString(prov.GUID); err != nil {
		return
	}

	params := EnableTraceParameters{
		Version: 2,
	}

	if err = EnableTraceEx2(
		p.sessionHandle,
		guid,
		EVENT_CONTROL_CODE_ENABLE_PROVIDER,
		uint8(prov.EnableLevel),
		prov.MatchAnyKeyword,
		prov.MatchAllKeyword,
		0,
		&params,
	); err != nil {
		return
	}

	p.Providers = append(p.Providers, prov.GUID)

	return
}

func (p *RealTimeSession) Start() (err error) {
	var u16TraceName *uint16

	if u16TraceName, err = syscall.UTF16PtrFromString(p.TraceName); err != nil {
		return err
	}

	if !p.Started() {
		if err = StartTrace(&p.sessionHandle, u16TraceName, p.properties); err != nil {
			// we handle the case where the trace already exists
			if err == ERROR_ALREADY_EXISTS {
				// we have to use a copy of properties as ControlTrace modifies
				// the structure and if we don't do that we cannot StartTrace later
				prop := *p.properties
				// we close the trace first
				ControlTrace(0, u16TraceName, &prop, EVENT_TRACE_CONTROL_STOP)
				return StartTrace(&p.sessionHandle, u16TraceName, p.properties)
			}
			return
		}
	}

	return
}

func (p *RealTimeSession) Stop() error {
	return ControlTrace(p.sessionHandle, nil, p.properties, EVENT_TRACE_CONTROL_STOP)
}
