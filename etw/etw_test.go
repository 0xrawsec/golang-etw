package etw

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	// providers
	SysmonProvider           = "{5770385F-C22A-43E0-BF4C-06F5698FFBD9}"
	KernelMemoryProviderName = "{D1D93EF7-E1F2-4F45-9943-03D245FE6C00}"

	// sessions
	EventlogSecurity = "Eventlog-Security"
)

func TestGUID(t *testing.T) {
	guid := "{45d8cccd-539f-4b72-a8b7-5c683142609a}"
	if g, err := GUIDFromString(guid); err != nil {
		t.Errorf("Failed to parse GUID: %s", err)
	} else {
		if strings.EqualFold(guid, g.String()) {
			t.Log(g)
		} else {
			t.Errorf("GUIDs are not equal %s != %s", guid, g)
		}
	}

	guid = "54849625-5478-4994-a5ba-3e3b0328c30d"
	if g, err := GUIDFromString(guid); err != nil {
		t.Errorf("Failed to parse GUID: %s", err)
	} else {
		if strings.EqualFold(fmt.Sprintf("{%s}", guid), g.String()) {
			t.Log(g)
		} else {
			t.Errorf("GUIDs are not equal %s != %s", guid, g)
		}
	}
}

func TestProducerConsumer(t *testing.T) {
	eventCount := 0

	p := NewRealTimeProducer("GolangTest")
	p.EnableVerboseProvider(SysmonProvider)
	if err := p.Start(); err != nil {
		t.Errorf("Failed to start trace: %s", err)
		t.FailNow()
	}
	if !p.Started() {
		t.Errorf("Producer should be running")
		t.FailNow()
	}
	defer p.Stop()

	c := NewRealTimeConsumer(context.Background())

	if err := c.OpenTraces(p.TraceName, "Eventlog-Security"); err != nil {
		t.Error(err)
		c.Stop()
		t.FailNow()
	}
	c.Start()

	start := time.Now()
	go func() {
		for e := range c.Events {
			//for range c.Events {
			eventCount++

			if b, err := json.Marshal(&e); err != nil {
				t.Errorf("Failed to marshal event: %s", err)
				t.FailNow()
			} else {
				t.Log(string(b))
			}
		}
	}()
	t.Log("Sleeping")
	time.Sleep(60 * time.Second)

	c.Stop()
	delta := time.Now().Sub(start)
	eps := float64(eventCount) / delta.Seconds()
	t.Logf("Received: %d events in %s (%d EPS)", eventCount, delta, int(eps))
}

func TestKernelSession(t *testing.T) {
	eventCount := 0

	traceFlags := []uint32{
		// Trace process creation / termination
		//EVENT_TRACE_FLAG_PROCESS,
		// Trace image loading
		//EVENT_TRACE_FLAG_IMAGE_LOAD,
		// Trace file operations
		//EVENT_TRACE_FLAG_FILE_IO_INIT,
		//EVENT_TRACE_FLAG_ALPC,
		EVENT_TRACE_FLAG_REGISTRY,
	}

	kp := NewKernelRealTimeProducer(traceFlags...)

	if err := kp.Start(); err != nil {
		t.Errorf("Failed to start trace: %s", err)
		t.FailNow()
	}
	if !kp.Started() {
		t.Errorf("Producer should be running")
		t.FailNow()
	}

	c := NewRealTimeConsumer(context.Background())
	//if err := c.OpenTraces(p.TraceName); err != nil {
	if err := c.OpenTraces(kp.TraceName); err != nil {
		t.Error(err)
		c.Stop()
		t.FailNow()
	}
	c.Start()

	start := time.Now()
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for e := range c.Events {
			//for range c.Events {
			eventCount++
			if b, err := json.Marshal(&e); err != nil {
				t.Errorf("Failed to marshal event: %s", err)
				t.FailNow()
			} else {
				t.Log(string(b))
			}
		}
	}()

	time.Sleep(60 * time.Second)

	kp.Stop()
	c.Stop()
	wg.Wait()

	delta := time.Now().Sub(start)
	eps := float64(eventCount) / delta.Seconds()
	t.Logf("Received: %d events in %s (%d EPS)", eventCount, delta, int(eps))
}
