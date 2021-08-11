package etw

import "time"

type EventID uint16

type Event struct {
	EventData map[string]interface{} `json:",omitempty"`
	UserData  map[string]interface{} `json:",omitempty"`
	System    struct {
		Channel   string
		Computer  string
		EventID   uint16
		EventType string `json:",omitempty"`
		EventGuid string `json:",omitempty"`
		Execution struct {
			ProcessID uint32
			ThreadID  uint32
		}
		Keywords struct {
			Value uint64
			Name  string
		}
		Level struct {
			Value uint8
			Name  string
		}
		Opcode struct {
			Value uint8
			Name  string
		}
		Task struct {
			Value uint8
			Name  string
		}
		Provider struct {
			Guid string
			Name string
		}
		TimeCreated struct {
			SystemTime time.Time
		}
	}
	ExtendedData []string `json:",omitempty"`
}

func (e *Event) ToMap() (m map[string]interface{}) {
	m = make(map[string]interface{})

	execution := make(map[string]interface{})
	execution["ProcessID"] = e.System.Execution.ProcessID
	execution["ThreadID"] = e.System.Execution.ThreadID

	keywords := make(map[string]interface{})
	keywords["Value"] = e.System.Keywords.Value
	keywords["Name"] = e.System.Keywords.Name

	level := make(map[string]interface{})
	level["Value"] = e.System.Level.Value
	level["Name"] = e.System.Level.Name

	opcode := make(map[string]interface{})
	opcode["Value"] = e.System.Opcode.Value
	opcode["Name"] = e.System.Opcode.Name

	task := make(map[string]interface{})
	task["Value"] = e.System.Task.Value
	task["Name"] = e.System.Task.Name

	provider := make(map[string]interface{})
	provider["Guid"] = e.System.Provider.Guid
	provider["Name"] = e.System.Provider.Name

	timecreated := make(map[string]interface{})
	timecreated["SystemTime"] = e.System.TimeCreated.SystemTime

	system := make(map[string]interface{})
	system["Channel"] = e.System.Channel
	system["Computer"] = e.System.Computer
	system["EventID"] = e.System.EventID
	if e.System.EventType != "" {
		system["EventType"] = e.System.EventType
	}
	if e.System.EventGuid != "" {
		system["EventGuid"] = e.System.EventGuid
	}
	system["Execution"] = execution
	system["Keywords"] = keywords
	system["Level"] = level
	system["Opcode"] = opcode
	system["Task"] = task
	system["Provider"] = provider
	system["TimeCreated"] = timecreated

	event := make(map[string]interface{})
	if len(e.UserData) > 0 {
		event["UserData"] = e.UserData
	} else {
		event["EventData"] = e.EventData
	}

	event["System"] = system

	if len(e.ExtendedData) > 0 {
		event["ExtendedData"] = e.ExtendedData
	}

	m["Event"] = event
	return
}
