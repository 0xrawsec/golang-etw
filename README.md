[![GoDoc](https://pkg.go.dev/badge/github.com/0xrawsec/golang-etw)](https://pkg.go.dev/github.com/0xrawsec/golang-etw/etw?GOOS=windows)
![Version](https://img.shields.io/github/v/tag/0xrawsec/golang-etw?label=version)
[![Coverage](https://raw.githubusercontent.com/0xrawsec/golang-etw/master/.github/coverage/badge.svg)](https://raw.githubusercontent.com/0xrawsec/golang-etw/master/.github/coverage/coverage.txt)

Golang library to consume ETW logs

## Examples

See [./examples](./examples)

```go
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/0xrawsec/golang-etw/etw"
)

func main() {
	// ETW needs a trace to be created before being able to consume from
	// it. Traces can be created using golang-etw or they might be already
	// existing (created from an autologgers for instance) like Eventlog-Security.

	// Creating the trace (producer part)
	s := etw.NewRealTimeSession("TestingGoEtw")

	// We have to stop the session or it will be kept alive and session name
	// will not be available anymore for next calls
	defer s.Stop()

	// we need to enable the trace to collect logs from given providers
	// several providers can be enabled per trace, in this example we
	// enable only one provider
	if err := s.EnableProvider(etw.MustParseProvider("Microsoft-Windows-Kernel-File")); err != nil {
		panic(err)
	}

	// Consuming from the trace
	c := etw.NewRealTimeConsumer(context.Background())

	defer c.Stop()

	c.FromSessions(s)

	// When events are parsed they get sent to Consumer's
	// Events channel by the default EventCallback method
	// EventCallback can be modified to do otherwise
	go func() {
		var b []byte
		var err error
		for e := range c.Events {
			if b, err = json.Marshal(e); err != nil {
				panic(err)
			}
			fmt.Println(string(b))
		}
	}()

	if err := c.Start(); err != nil {
		panic(err)
	}

	time.Sleep(5 * time.Second)

	if c.Err() != nil {
		panic(c.Err())
	}

}
```

## Related Documentation

- [Advanced ETWSession Configuration](https://docs.microsoft.com/en-us/message-analyzer/specifying-advanced-etw-session-configuration-settings)

## Related Work

- [ETW Explorer](https://github.com/zodiacon/EtwExplorer)
- [ETWProviders](https://github.com/repnz/etw-providers-docs)
