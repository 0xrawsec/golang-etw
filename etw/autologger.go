//go:build windows
// +build windows

package etw

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

const (
	AutologgerPath = `HKLM\System\CurrentControlSet\Control\WMI\Autologger`

	regDword = "REG_DWORD"
	regQword = "REG_QWORD"
	regSz    = "REG_SZ"
)

var (
	DefaultAutologgerEnableLevel = 255
)

func hexStr(i interface{}) string {
	return fmt.Sprintf("0x%x", i)
}

type AutoLogger struct {
	Name        string
	Guid        string
	LogFileMode uint32
	BufferSize  uint32
	ClockType   uint32
}

func (a *AutoLogger) Path() string {
	return fmt.Sprintf(`%s\%s`, strings.TrimRight(AutologgerPath, `\`), strings.TrimLeft(a.Name, `\`))
}

func (a *AutoLogger) Create() (err error) {
	sargs := [][]string{
		// ETW trace parameters
		{a.Path(), "GUID", regSz, a.Guid},
		{a.Path(), "Start", regDword, "0x1"},
		{a.Path(), "LogFileMode", regDword, hexStr(a.LogFileMode)},
		// ETW event can be up to 64KB so buffer needs to be at least this size
		{a.Path(), "BufferSize", regDword, hexStr(a.BufferSize)},
		{a.Path(), "ClockType", regDword, hexStr(a.ClockType)},
	}

	for _, args := range sargs {
		if err = regAddValue(args[0], args[1], args[2], args[3]); err != nil {
			return
		}
	}

	return
}

func (a *AutoLogger) EnableProvider(p Provider) (err error) {
	path := fmt.Sprintf(`%s\%s`, a.Path(), p.GUID)

	sargs := [][]string{}

	// ETW trace parameters
	if p.Name != "" {
		sargs = append(sargs, []string{path, "ProviderName", regSz, p.Name})
	}

	sargs = append(sargs, []string{path, "Enabled", regDword, "0x1"})
	sargs = append(sargs, []string{path, "EnableLevel", regDword, hexStr(p.EnableLevel)})
	sargs = append(sargs, []string{path, "MatchAnyKeyword", regQword, hexStr(p.MatchAnyKeyword)})

	if p.MatchAnyKeyword != 0 {
		sargs = append(sargs, []string{path, "MatchAllKeyword", regQword, hexStr(p.MatchAllKeyword)})
	}

	for _, args := range sargs {
		if err = regAddValue(args[0], args[1], args[2], args[3]); err != nil {
			return
		}
	}
	return
}

func (a *AutoLogger) Exists() bool {
	return execute("reg.exe", "QUERY", a.Path()) == nil
}

func (a *AutoLogger) Delete() error {
	return execute("reg.exe", "DELETE", a.Path(), "/f")
}

func execute(name string, args ...string) error {
	ctx, _ := context.WithTimeout(context.Background(), time.Second*10)
	if out, err := exec.CommandContext(ctx, name, args...).CombinedOutput(); err != nil {
		return fmt.Errorf("%s", string(out))
	}
	return nil
}

func regAddValue(path, valueName, valueType, value string) error {
	return execute("reg.exe", "ADD", path, "/v", valueName, "/t", valueType, "/d", value, "/f")
}
