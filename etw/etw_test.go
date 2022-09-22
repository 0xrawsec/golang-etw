//go:build windows
// +build windows

package etw

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/0xrawsec/toast"
)

const (
	// providers
	SysmonProvider           = "{5770385F-C22A-43E0-BF4C-06F5698FFBD9}"
	KernelMemoryProviderName = "{D1D93EF7-E1F2-4F45-9943-03D245FE6C00}"
	KernelFileProviderName   = "Microsoft-Windows-Kernel-File"
	// sessions
	EventlogSecurity = "Eventlog-Security"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

func randBetween(min, max int) (i int) {
	for ; i < min; i = rand.Int() % max {
	}
	return
}

func TestIsKnownProvider(t *testing.T) {
	t.Parallel()

	tt := toast.FromT(t)

	tt.Assert(IsKnownProvider("Microsoft-Windows-Kernel-File"))
	tt.Assert(!IsKnownProvider("Microsoft-Windows-Unknown-Provider"))
}

func TestProducerConsumer(t *testing.T) {
	var prov Provider
	var err error

	eventCount := 0
	tt := toast.FromT(t)

	// Producer part
	prod := NewRealTimeSession("GolangTest")

	prov, err = ParseProvider(KernelFileProviderName + ":0xff:12,13,14,15,16")
	tt.CheckErr(err)
	// enabling provider
	tt.CheckErr(prod.EnableProvider(prov))
	// starting producer
	tt.CheckErr(prod.Start())
	// checking producer is running
	tt.Assert(prod.IsStarted())

	defer prod.Stop()

	// Consumer part
	c := NewRealTimeConsumer(context.Background()).FromSessions(prod).FromTraceNames(EventlogSecurity)

	// we have to declare a func otherwise c.Stop seems to be called
	defer func() { tt.CheckErr(c.Stop()) }()
	// starting consumer
	tt.CheckErr(c.Start())

	start := time.Now()
	// consuming events in Golang
	go func() {
		for e := range c.Events {
			eventCount++

			if e.System.Provider.Name == KernelFileProviderName {
				tt.Assert(e.System.EventID == 12 ||
					e.System.EventID == 13 ||
					e.System.EventID == 14 ||
					e.System.EventID == 15 ||
					e.System.EventID == 16)
			}

			_, err := json.Marshal(&e)
			tt.CheckErr(err)
			//t.Log(string(b))
		}
	}()
	// sleeping
	time.Sleep(5 * time.Second)

	// stopping consumer
	tt.CheckErr(c.Stop())
	delta := time.Now().Sub(start)
	eps := float64(eventCount) / delta.Seconds()
	t.Logf("Received: %d events in %s (%d EPS)", eventCount, delta, int(eps))

	// checking any consumer error
	tt.CheckErr(c.Err())
}

func TestKernelSession(t *testing.T) {
	tt := toast.FromT(t)
	eventCount := 0

	traceFlags := []uint32{
		// Trace process creation / termination
		//EVENT_TRACE_FLAG_PROCESS,
		// Trace image loading
		EVENT_TRACE_FLAG_IMAGE_LOAD,
		// Trace file operations
		//EVENT_TRACE_FLAG_FILE_IO_INIT,
		//EVENT_TRACE_FLAG_ALPC,
		EVENT_TRACE_FLAG_REGISTRY,
	}

	// producer part
	kp := NewKernelRealTimeSession(traceFlags...)

	// starting kernel producer
	tt.CheckErr(kp.Start())
	// checking producer is started
	tt.Assert(kp.IsStarted())

	// consumer part
	c := NewRealTimeConsumer(context.Background()).FromSessions(kp)

	// we have to declare a func otherwise c.Stop seems to be called
	defer func() { tt.CheckErr(c.Stop()) }()

	tt.CheckErr(c.Start())

	start := time.Now()
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for e := range c.Events {
			eventCount++

			_, err := json.Marshal(&e)
			tt.CheckErr(err)
			//t.Log(string(b))
		}
	}()

	time.Sleep(5 * time.Second)

	tt.CheckErr(c.Stop())
	tt.CheckErr(kp.Stop())
	wg.Wait()

	delta := time.Since(start)
	eps := float64(eventCount) / delta.Seconds()
	t.Logf("Received: %d events in %s (%d EPS)", eventCount, delta, int(eps))
}

func TestEventMapInfo(t *testing.T) {
	tt := toast.FromT(t)
	eventCount := 0

	prod := NewRealTimeSession("GolangTest")

	mapInfoChannels := []string{
		"Microsoft-Windows-ProcessStateManager",
		"Microsoft-Windows-DNS-Client",
		"Microsoft-Windows-Win32k",
		"Microsoft-Windows-RPC",
		"Microsoft-Windows-Kernel-IoTrace"}

	for _, c := range mapInfoChannels {
		t.Log(c)
		prov, err := ParseProvider(c)
		tt.CheckErr(err)
		tt.CheckErr(prod.EnableProvider(prov))
	}

	// starting producer
	tt.CheckErr(prod.Start())
	// checking producer is running
	tt.Assert(prod.IsStarted())

	defer prod.Stop()

	// consumer part
	fakeError := fmt.Errorf("fake")

	c := NewRealTimeConsumer(context.Background()).FromSessions(prod)
	// reducing size of channel so that we are obliged to skip events
	c.Events = make(chan *Event)
	c.PreparedCallback = func(erh *EventRecordHelper) error {

		erh.TraceInfo.EventMessage()
		erh.TraceInfo.ActivityIDName()
		erh.TraceInfo.RelatedActivityIDName()

		erh.Skip()

		for _, p := range erh.Properties {
			// calling those two method just to test they don't cause memory corruption
			p.evtPropInfo.Count()
			p.evtPropInfo.CountPropertyIndex()
			if p.evtPropInfo.MapNameOffset() > 0 {
				erh.Flags.Skip = false
			}
		}

		// don't skip events with related activity ID
		erh.Flags.Skip = erh.EventRec.RelatedActivityID() == nullGUIDStr

		return fakeError
	}

	// we have to declare a func otherwise c.Stop seems to be called
	defer func() { tt.CheckErr(c.Stop()) }()

	tt.CheckErr(c.Start())

	start := time.Now()
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for e := range c.Events {
			eventCount++

			_, err := json.Marshal(&e)
			tt.CheckErr(err)
			if e.System.Correlation.ActivityID != nullGUIDStr && e.System.Correlation.RelatedActivityID != nullGUIDStr {
				t.Logf("Provider=%s ActivityID=%s RelatedActivityID=%s", e.System.Provider.Name, e.System.Correlation.ActivityID, e.System.Correlation.RelatedActivityID)
			}
			//t.Log(string(b))
		}
	}()

	time.Sleep(10 * time.Second)

	tt.CheckErr(c.Stop())
	wg.Wait()

	// we got many events so some must have been skipped
	t.Logf("skipped %d events", c.Skipped)
	tt.Assert(c.Skipped == 0)

	delta := time.Since(start)
	eps := float64(eventCount) / delta.Seconds()
	t.Logf("Received: %d events in %s (%d EPS)", eventCount, delta, int(eps))

	tt.ExpectErr(c.Err(), fakeError)
}

func TestLostEvents(t *testing.T) {

	tt := toast.FromT(t)

	// Producer part
	prod := NewRealTimeSession("GolangTest")
	// small buffer size on purpose to trigger event loss
	prod.properties.BufferSize = 1

	prov, err := ParseProvider("Microsoft-Windows-Kernel-Memory" + ":0xff")
	tt.CheckErr(err)
	// enabling provider
	tt.CheckErr(prod.EnableProvider(prov))
	defer prod.Stop()

	// Consumer part
	c := NewRealTimeConsumer(context.Background()).FromSessions(prod).FromTraceNames(EventlogSecurity)
	// we have to declare a func otherwise c.Stop does not seem to be called
	defer func() { tt.CheckErr(c.Stop()) }()

	// starting consumer
	tt.CheckErr(c.Start())
	cnt := uint64(0)
	go func() {
		for range c.Events {
			cnt++
		}
	}()
	time.Sleep(20 * time.Second)
	tt.CheckErr(c.Stop())
	time.Sleep(5 * time.Second)
	t.Logf("Events received: %d", cnt)
	t.Logf("Events lost: %d", c.LostEvents)
	tt.Assert(c.LostEvents > 0)
}

func jsonStr(i interface{}) string {
	var b []byte
	var err error
	if b, err = json.Marshal(i); err != nil {
		panic(err)
	}
	return string(b)
}

func TestConsumerCallbacks(t *testing.T) {
	var prov Provider
	var err error

	eventCount := 0
	tt := toast.FromT(t)

	// Producer part
	prod := NewRealTimeSession("GolangTest")

	prov, err = ParseProvider(KernelFileProviderName + ":0xff:12,13,14,15,16")
	tt.CheckErr(err)
	// enabling provider
	tt.CheckErr(prod.EnableProvider(prov))
	// starting producer
	tt.CheckErr(prod.Start())
	// checking producer is running
	tt.Assert(prod.IsStarted())
	kernelFileProviderChannel := prov.Name + "/Analytic"
	kernelProviderGUID := MustParseGUIDFromString(prov.GUID)

	defer prod.Stop()

	// Consumer part
	c := NewRealTimeConsumer(context.Background()).FromSessions(prod).FromTraceNames(EventlogSecurity)

	c.EventRecordHelperCallback = func(erh *EventRecordHelper) (err error) {

		switch erh.EventID() {
		case 12, 14, 15, 16:
			break
		default:
			erh.Skip()
		}

		return
	}

	type file struct {
		name  string
		flags struct {
			read  bool
			write bool
		}
	}

	fileObjectMapping := make(map[string]*file)
	c.PreparedCallback = func(h *EventRecordHelper) error {
		tt.Assert(h.Provider() == prov.Name)
		tt.Assert(h.ProviderGUID() == prov.GUID)
		tt.Assert(h.EventRec.EventHeader.ProviderId.Equals(kernelProviderGUID))
		tt.Assert(h.TraceInfo.ProviderGUID.Equals(kernelProviderGUID))
		tt.Assert(h.Channel() == kernelFileProviderChannel)

		switch h.EventID() {
		case 12:
			tt.CheckErr(h.ParseProperties("FileName", "FileObject", "CreateOptions"))

			if fo, err := h.GetPropertyString("FileObject"); err == nil {
				if fn, err := h.GetPropertyString("FileName"); err == nil {
					fileObjectMapping[fo] = &file{name: fn}
				}
			}

			coUint, err := h.GetPropertyUint("CreateOptions")
			tt.CheckErr(err)
			coInt, err := h.GetPropertyInt("CreateOptions")
			tt.CheckErr(err)
			tt.Assert(coUint != 0 && coUint == uint64(coInt))

			unk, err := h.GetPropertyString("UnknownProperty")
			tt.Assert(unk == "")
			tt.ExpectErr(err, ErrUnknownProperty)

			// we skip file create events
			h.Skip()

		case 14:
			tt.CheckErr(h.ParseProperties("FileObject"))

			if object, err := h.GetPropertyString("FileObject"); err == nil {
				delete(fileObjectMapping, object)
			}

			// skip file close events
			h.Skip()

		case 15, 16:
			var f *file
			var object string
			var ok bool

			tt.CheckErr(h.ParseProperty("FileObject"))

			if object, err = h.GetPropertyString("FileObject"); err != nil {
				h.Skip()
				break
			}

			foUint, _ := h.GetPropertyUint("FileObject")
			tt.Assert(fmt.Sprintf("0x%X", foUint) == object)

			if f, ok = fileObjectMapping[object]; !ok {
				// we skip events we cannot enrich
				h.Skip()
				break
			}

			if (h.EventID() == 15 && f.flags.read) ||
				(h.EventID() == 16 && f.flags.write) {
				h.Skip()
				break
			}

			h.SetProperty("FileName", f.name)
			f.flags.read = (h.EventID() == 15)
			f.flags.write = (h.EventID() == 16)

			// event volume will so low that this call should have no effect
			h.Skippable()

		default:
			h.Skip()
		}

		return nil
	}

	// we have to declare a func otherwise c.Stop does not seem to be called
	defer func() { tt.CheckErr(c.Stop()) }()

	// starting consumer
	tt.CheckErr(c.Start())

	//testfile := `\Windows\Temp\test.txt`
	testfile := filepath.Join(t.TempDir()[2:], "test.txt")
	t.Logf("testfile: %s", testfile)

	start := time.Now()
	var etwread int
	var etwwrite int

	pid := os.Getpid()
	// consuming events in Golang
	go func() {
		for e := range c.Events {
			eventCount++

			_, err := json.Marshal(&e)
			tt.CheckErr(err)
			switch e.System.EventID {
			case 15, 16:
				var fn string
				var ok bool

				if fn, ok = e.GetPropertyString("FileName"); !ok {
					break
				}

				if !strings.Contains(fn, testfile) {
					break
				}

				if e.System.Execution.ProcessID != uint32(pid) {
					break
				}

				if e.System.EventID == 15 {
					etwread++
				} else {
					etwwrite++
				}
			}
		}
	}()

	// creating test files
	nReadWrite := 0
	tf := fmt.Sprintf("C:%s", testfile)
	for ; nReadWrite < randBetween(800, 1000); nReadWrite++ {
		tmp := fmt.Sprintf("%s.%d", tf, nReadWrite)
		tt.CheckErr(os.WriteFile(tmp, []byte("testdata"), 7777))
		_, err = os.ReadFile(tmp)
		tt.CheckErr(err)
		time.Sleep(time.Millisecond)
	}

	d := time.Duration(0)
	sleep := time.Second
	for d < 10*time.Second {
		if etwread == nReadWrite && etwwrite == nReadWrite {
			break
		}
		time.Sleep(sleep)
		d += sleep
	}

	// wait a couple of seconds more to see if we get more events
	time.Sleep(10 * time.Second)

	// stopping consumer
	tt.CheckErr(c.Stop())

	tt.Assert(eventCount != 0, "did not receive any event")
	tt.Assert(c.Skipped == 0)
	// verifying that we caught all events
	t.Logf("read=%d etwread=%d", nReadWrite, etwread)
	tt.Assert(nReadWrite == etwread)
	t.Logf("write=%d etwwrite=%d", nReadWrite, etwwrite)
	tt.Assert(nReadWrite == etwwrite)

	delta := time.Since(start)
	eps := float64(eventCount) / delta.Seconds()
	t.Logf("Received: %d events in %s (%d EPS)", eventCount, delta, int(eps))

	// checking any consumer error
	tt.CheckErr(c.Err())
}

func TestParseProvider(t *testing.T) {
	t.Parallel()

	tt := toast.FromT(t)

	if _, err := ParseProvider(KernelFileProviderName); err != nil {
		t.Error(err)
	}

	p, err := ParseProvider(KernelFileProviderName + ":255")
	tt.CheckErr(err)
	tt.Assert(p.EnableLevel == 255)

	p, err = ParseProvider(KernelFileProviderName + ":255:0,1,2,3,4:4242")
	tt.CheckErr(err)
	for i, eventID := range p.Filter {
		tt.Assert(i == int(eventID))
	}

	p, err = ParseProvider(KernelFileProviderName + ":255:1,2,3,4:4242")
	tt.CheckErr(err)
	tt.Assert(p.EnableLevel == 255 && p.MatchAnyKeyword == 4242)

	p, err = ParseProvider(KernelFileProviderName + ":255:1,2,3,4:4242:1337")
	tt.CheckErr(err)
	tt.Assert(p.EnableLevel == 255 && p.MatchAnyKeyword == 4242 && p.MatchAllKeyword == 1337)

	// this calls must panic on error
	MustParseProvider(KernelFileProviderName)
	tt.ShouldPanic(func() { MustParseProvider("Microsoft-Unknown-Provider") })
}

func TestConvertSid(t *testing.T) {
	t.Parallel()

	var sid *SID
	var err error

	tt := toast.FromT(t)
	systemSID := "S-1-5-18"

	sid, err = ConvertStringSidToSidW(systemSID)
	tt.CheckErr(err)
	tt.Log(sid)
}

func TestSessionSlice(t *testing.T) {
	t.Parallel()

	tt := toast.FromT(t)

	intSlice := make([]int, 0)
	sessions := make([]Session, 0)
	for i := 0; i < 10; i++ {
		sessions = append(sessions, NewRealTimeSession(fmt.Sprintf("test-%d", i)))
		intSlice = append(intSlice, i)
	}

	tt.Assert(len(SessionSlice(sessions)) == len(sessions))
	// should panic because parameter is not a slice
	tt.ShouldPanic(func() { SessionSlice(sessions[0]) })
	// should panic because items do not implement Session
	tt.ShouldPanic(func() { SessionSlice(intSlice) })
}
