package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/0xrawsec/golang-etw/etw"
	"github.com/0xrawsec/golang-utils/log"
)

const (
	copyright = "etwdump Copyright (C) 2022 RawSec SARL (@0xrawsec)"
	license   = `GPLv3: This program comes with ABSOLUTELY NO WARRANTY.`
)

func clear() {
	cmd := exec.Command("cmd", "/c", "cls")
	cmd.Stdout = os.Stdout
	cmd.Run()
}

type EventWrapper struct {
	Event *etw.Event
}

func getAccessString(guid string) (s string) {
	var err error

	if s, err = etw.GetAccessString(guid); err != nil {
		panic(err)
	}

	return
}

func setAccess(guid string) {
	var sid *etw.SID
	var err error

	if sid, err = etw.ConvertStringSidToSidW("S-1-5-18"); err != nil {
		log.Errorf("Failed to convert string to sid%s", err)
		return
	}
	g := etw.MustParseGUIDFromString(guid)

	if err = etw.EventAccessControl(g,
		uint32(etw.EVENT_SECURITY_SET_DACL),
		sid,
		0x120fff,
		true,
	); err != nil {
		log.Errorf("Failed to set access%s", err)
	}
}

func parseFilter(s string) (provider string, eventIds []uint16) {
	eventIds = make([]uint16, 0)
	split := strings.Split(s, ":")
	if len(split) == 2 {
		provider = split[0]
		for _, ss := range strings.Split(split[1], ",") {
			if eventId, err := strconv.ParseUint(ss, 10, 16); err == nil {
				eventIds = append(eventIds, uint16(eventId))
			}
		}
	}
	return
}

func unsafeRandomGuid() *etw.GUID {
	// not safe as determininstic
	rand.Seed(time.Now().UnixNano())
	return &etw.GUID{
		Data1: rand.Uint32(),
		Data2: uint16(rand.Uint32()),
		Data3: uint16(rand.Uint32()),
		Data4: [8]byte{
			uint8(rand.Uint32()),
			uint8(rand.Uint32()),
			uint8(rand.Uint32()),
			uint8(rand.Uint32()),
			uint8(rand.Uint32()),
			uint8(rand.Uint32()),
			uint8(rand.Uint32()),
			uint8(rand.Uint32()),
		},
	}
}

func providerOrFail(s string) etw.Provider {
	if prov, err := etw.ParseProvider(s); err != nil {
		log.Abort(1, err)
		return prov
	} else {
		return prov
	}
}

type Stats struct {
	sync.RWMutex
	s      map[string]map[uint16]uint64
	start  time.Time
	update time.Time
	Count  uint64
}

func NewStats() *Stats {
	return &Stats{
		s: make(map[string]map[uint16]uint64),
	}
}

func (s *Stats) Update(e *etw.Event) {
	s.Lock()
	defer s.Unlock()

	var ok bool
	var eventIDs map[uint16]uint64

	now := time.Now()

	key := e.System.Channel
	if key == "" {
		key = e.System.Provider.Guid
	}

	if eventIDs, ok = s.s[key]; !ok {
		eventIDs = make(map[uint16]uint64)
		s.s[key] = eventIDs
	}

	eventIDs[e.System.EventID]++
	s.Count++

	if s.start.IsZero() {
		s.start = now
	}

	s.update = now
}

func (s *Stats) Show() {
	s.RLock()
	defer s.RUnlock()

	delta := float64(s.update.Unix() - s.start.Unix())
	channels := make(sort.StringSlice, 0, len(s.s))
	for c := range s.s {
		channels = append(channels, c)
	}
	sort.Sort(channels)
	for _, c := range channels {
		chanCount := uint64(0)
		ids := make(sort.IntSlice, 0, len(s.s[c]))
		for id, cnt := range s.s[c] {
			ids = append(ids, int(id))
			chanCount += cnt
		}
		sort.Sort(ids)
		// Printing output
		chanEps := float64(chanCount) / delta
		fmt.Printf("%s: %d (%.2f EPS)\n", c, chanCount, chanEps)
		for _, id := range ids {
			count := s.s[c][uint16(id)]
			eps := float64(count) / delta
			fmt.Printf("\t%d: %d (%.2f EPS)\n", id, count, eps)
		}
	}
	globEps := float64(s.Count) / delta
	fmt.Printf("Global: %d (%.2f EPS)", s.Count, globEps)
}

func main() {
	var (
		debug               bool
		listKernelProviders bool
		listProviders       bool
		access              bool
		set                 bool
		noout               bool
		fstats              bool
		filemon             bool
		attach              string
		regex               string
		outfile             string
		autologger          string
		cregex              *regexp.Regexp
		kernelTraceFlags    uint32

		producers []*etw.RealTimeSession

		sessionName = "EtwdumpTraceSession"
		sessions    = make([]string, 0)
		writer      = os.Stdout
		stats       = NewStats()
	)

	flag.StringVar(&sessionName, "s", sessionName, "ETW session name")
	flag.StringVar(&attach, "a", attach, "Attach to existing session(s) (comma separated)")
	flag.StringVar(&regex, "e", regex, "Regex to filter in events or providers when listed")
	flag.StringVar(&outfile, "o", outfile, "Output file")
	flag.StringVar(&autologger, "autologger", autologger, "Creates autologger and enables providers")
	flag.BoolVar(&access, "access", access, "List accesses to GUIDs")
	flag.BoolVar(&set, "set", set, "Set accesses to GUIDs")
	flag.BoolVar(&debug, "debug", debug, "Enable debug messages")
	flag.BoolVar(&listKernelProviders, "lk", listKernelProviders, "List kernel providers")
	flag.BoolVar(&listProviders, "lp", listProviders, "List providers")
	flag.BoolVar(&noout, "noout", noout, "Do not write logs")
	flag.BoolVar(&fstats, "stats", fstats, "Show statistics about events")
	flag.BoolVar(&filemon, "filemon", filemon, "Monitor file read/writes")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "%s\n%s\n", copyright, license)
		fmt.Fprintf(os.Stderr, "Version: %s (commit: %s)\n\n", version, commitID)
		fmt.Fprintf(os.Stderr, "Usage: %s [OPTIONS] PROVIDERS...\n", filepath.Base(os.Args[0]))
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		os.Exit(0)
	}

	flag.Parse()

	if debug {
		log.SetLogLevel(log.LDebug)
	}

	providers := flag.Args()
	if filemon {
		if len(attach) == 0 {
			providers = []string{FilemonKernelProcessProvider, FilemonProvider}
		}
	}

	log.Debugf("PID: %d", os.Getpid())

	// list kernel providers
	if listKernelProviders {
		fmt.Println("Kernel Providers")
		for _, pd := range etw.KernelProviders {
			fmt.Printf("\t%s: %s\n", pd.Name, pd.GUID)
		}
		os.Exit(0)
	}

	// build up regex
	if regex != "" {
		cregex = regexp.MustCompile(regex)
	}

	if listProviders {
		pmap := etw.EnumerateProviders()
		names := make([]string, 0, len(pmap))
		maxLen := 0
		for name, prov := range pmap {
			// we don't want do display GUID keys
			if name == prov.GUID {
				continue
			}
			if cregex != nil {
				if !cregex.MatchString(name) {
					continue
				}
			}
			if len(name) > maxLen {
				maxLen = len(name)
			}
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			fmt.Printf("%s%s %s\n", name, strings.Repeat(" ", maxLen-len(name)), pmap[name].GUID)
		}
		os.Exit(0)
	}

	if access {
		if set {
			for _, provider := range providers {
				setAccess(providerOrFail(provider).GUID)
			}
		}

		fmt.Println("Listing access rights")
		for _, provider := range providers {
			//fmt.Printf("%s: %s\n", provider, getAccessString(providerOrFail(provider).GUID))
			fmt.Printf("%s: %s\n", provider, getAccessString(provider))
		}
		os.Exit(0)
	}

	// opening output file if needed
	if outfile != "" {
		if fd, err := os.Create(outfile); err != nil {
			log.Errorf("Failed to open output file: %s", err)
		} else {
			writer = fd
		}
	}

	if autologger != "" {
		a := etw.AutoLogger{
			Name:        autologger,
			Guid:        unsafeRandomGuid().String(),
			LogFileMode: 0x8001c0,
			BufferSize:  64,
			ClockType:   2,
		}

		if !a.Exists() {
			a.Create()
		}

		for _, provider := range providers {
			var p etw.Provider
			var err error
			if etw.IsKernelProvider(provider) {
				continue

			}

			if p, err = etw.ParseProvider(provider); err != nil {
				log.Abort(1, err)
			}

			if err = a.EnableProvider(p); err != nil {
				log.Abort(1, fmt.Errorf("Failed to enable provider: %s", err))
			}
		}

		os.Exit(0)
	}

	// We create a private producer
	p := etw.NewRealTimeSession(sessionName)

	// We process the providers provided in the command line
	for _, provStr := range providers {
		// this is a kernel provider
		if etw.IsKernelProvider(provStr) {
			log.Debugf("Enabling kernel provider: %s", provStr)
			kernelTraceFlags |= etw.GetKernelProviderFlags(provStr)
		} else {
			if prov, err := etw.ParseProvider(provStr); err != nil {
				log.Errorf("Failed to parse provider %s: %s", provStr, err)
			} else {
				log.Debugf("Enabling provider: %s", provStr)
				if err := p.EnableProvider(prov); err != nil {
					log.Errorf("Failed to enable provider %s: %s", provStr, err)
				}
			}
		}
	}

	// We enable producer only if it has at least a provider
	if len(p.Providers()) > 0 {
		producers = append(producers, p)
	}

	// We will start kernel producer only if necessary
	if kernelTraceFlags != 0 {
		kp := etw.NewKernelRealTimeSession(kernelTraceFlags)
		producers = append(producers, kp)
	}

	for _, p := range producers {
		log.Debugf("Starting producer: %s", p.TraceName())
		if err := p.Start(); err != nil {
			panic(err)
		}
		sessions = append(sessions, p.TraceName())
	}

	/** Consumer part **/

	// additional sessions to trace (already started)
	if attach != "" {
		sessions = append(sessions, strings.Split(attach, ",")...)
	}

	c := etw.NewRealTimeConsumer(context.Background()).
		FromSessions(etw.SessionSlice(producers)...).
		FromTraceNames(sessions...)

	c.InitFilters(p.Providers())

	if filemon {
		c.EventRecordCallback = filemonEventRecordCB

		c.PreparedCallback = filemonPreparedCB
		if cregex != nil {
			filemonRegex = cregex
			// don't use it to filter events
			cregex = nil
		}
	}

	if err := c.Start(); err != nil {
		log.Abort(1, "Failed to start traces: %s", err)
	}

	// Signal handler to catch interrupt
	h := make(chan os.Signal, 1)
	interrupt := sync.WaitGroup{}
	signal.Notify(h, os.Interrupt)

	interrupt.Add(1)
	go func() {
		defer interrupt.Done()

		<-h
		log.Infof("Received signal Interrupt")

		// we need to stop consumer first otherwise we trigger
		// some windows exception (probably due to access to freed memory)
		log.Debug("Stopping consumer")
		if err := c.Stop(); err != nil {
			log.Errorf("Error while stopping consumer: %s", err)
		}

		log.Infof("Skipped: %d", c.Skipped)

		log.Debug("Stopping producers")
		for _, p := range producers {
			if err := p.Stop(); err != nil {
				log.Errorf("Failed to stop producer: %s", err)
			}
		}

	}()

	go func() {
		log.Debug("Consuming events")
		for e := range c.Events {
			if fstats {
				stats.Update(e)
				if stats.Count%200 == 0 {
					clear()
					stats.Show()
				}
				// we write to output if needed
				if outfile != "" {
					if b, err := json.Marshal(EventWrapper{e}); err != nil {
						panic(err)
					} else {
						fmt.Fprintf(writer, "%s\n", string(b))
					}
				}
				continue
			}

			if b, err := json.Marshal(EventWrapper{e}); err != nil {
				panic(err)
			} else {
				if cregex != nil {
					if cregex.Match(b) {
						if !noout {
							fmt.Fprintf(writer, "%s\n", string(b))
						}
					}
				} else {
					if !noout {
						fmt.Fprintf(writer, "%s\n", string(b))
					}
				}
			}
		}
	}()

	c.Wait()
	interrupt.Wait()
}
