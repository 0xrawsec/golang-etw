package etw

import "time"

type EventID uint16

type Event struct {
	Event struct {
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
}

func (e *Event) ToMap() (m map[string]interface{}) {
	m = make(map[string]interface{})

	execution := make(map[string]interface{})
	execution["ProcessID"] = e.Event.System.Execution.ProcessID
	execution["ThreadID"] = e.Event.System.Execution.ThreadID

	keywords := make(map[string]interface{})
	keywords["Value"] = e.Event.System.Keywords.Value
	keywords["Name"] = e.Event.System.Keywords.Name

	level := make(map[string]interface{})
	level["Value"] = e.Event.System.Level.Value
	level["Name"] = e.Event.System.Level.Name

	opcode := make(map[string]interface{})
	opcode["Value"] = e.Event.System.Opcode.Value
	opcode["Name"] = e.Event.System.Opcode.Name

	task := make(map[string]interface{})
	task["Value"] = e.Event.System.Task.Value
	task["Name"] = e.Event.System.Task.Name

	provider := make(map[string]interface{})
	provider["Guid"] = e.Event.System.Provider.Guid
	provider["Name"] = e.Event.System.Provider.Name

	timecreated := make(map[string]interface{})
	timecreated["SystemTime"] = e.Event.System.TimeCreated.SystemTime

	system := make(map[string]interface{})
	system["Channel"] = e.Event.System.Channel
	system["Computer"] = e.Event.System.Computer
	system["EventID"] = e.Event.System.EventID
	if e.Event.System.EventType != "" {
		system["EventType"] = e.Event.System.EventType
	}
	if e.Event.System.EventGuid != "" {
		system["EventGuid"] = e.Event.System.EventGuid
	}
	system["Execution"] = execution
	system["Keywords"] = keywords
	system["Level"] = level
	system["Opcode"] = opcode
	system["Task"] = task
	system["Provider"] = provider
	system["TimeCreated"] = timecreated

	event := make(map[string]interface{})
	if len(e.Event.UserData) > 0 {
		event["UserData"] = e.Event.UserData
	} else {
		event["EventData"] = e.Event.EventData
	}

	event["System"] = system

	if len(e.Event.ExtendedData) > 0 {
		event["ExtendedData"] = e.Event.ExtendedData
	}

	m["Event"] = event
	return
}
