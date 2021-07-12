// +build windows

package etw

import (
	"fmt"
	"math"
	"os"
	"syscall"
	"unsafe"

	"github.com/0xrawsec/golang-utils/log"
)

var (
	hostname, _ = os.Hostname()
)

func NewEvent() (e *Event) {
	e = &Event{}
	e.Event.EventData = make(map[string]interface{})
	e.Event.UserData = make(map[string]interface{})
	e.Event.ExtendedData = make([]string, 0)
	return e
}

type EventRecordHelper struct {
	Event      *EventRecord
	TraceInfo  *TraceEventInfo
	userDataIt uintptr
}

func NewEventRecordHelper(er *EventRecord) (erh *EventRecordHelper, err error) {
	erh = &EventRecordHelper{}
	erh.Event = er
	if erh.TraceInfo, err = er.GetEventInformation(); err != nil {
		return
	}
	erh.userDataIt = er.UserData
	return
}

func (e *EventRecordHelper) EndUserData() uintptr {
	return e.Event.UserData + uintptr(e.Event.UserDataLength)
}

func (e *EventRecordHelper) UserDataLength() uint16 {
	return uint16(e.EndUserData() - e.userDataIt)
}

func (e *EventRecordHelper) GetPropertyLength(i uint32) (uint32, error) {
	if epi := e.TraceInfo.GetEventPropertyInfoAt(i); epi.Flags&PropertyParamLength == PropertyParamLength {
		propSize := uint32(0)
		length := uint32(0)
		j := uint32(epi.LengthPropertyIndex())
		pdd := PropertyDataDescriptor{}
		pdd.PropertyName = uint64(e.TraceInfo.pointer()) + uint64(e.TraceInfo.GetEventPropertyInfoAt(j).NameOffset)
		pdd.ArrayIndex = math.MaxUint32
		if err := TdhGetPropertySize(e.Event, 0, nil, 1, &pdd, &propSize); err != nil {
			return 0, fmt.Errorf("failed to get property size: %s", err)
		} else {
			if err := TdhGetProperty(e.Event, 0, nil, 1, &pdd, propSize, (*byte)(unsafe.Pointer(&length))); err != nil {
				return 0, fmt.Errorf("failed to get property: %s", err)
			}
			return length, nil
		}
	} else {
		if epi.Length() > 0 {
			return uint32(epi.Length()), nil
		} else {
			switch {
			// if there is an error returned here just try to add a switch case
			// with the propert in type
			case epi.InType() == uint16(TdhInTypeBinary) && epi.OutType() == uint16(TdhOutTypeIpv6):
				// sizeof(IN6_ADDR) == 16
				return uint32(16), nil
			case epi.InType() == uint16(TdhInTypeUnicodestring):
				return uint32(epi.Length()), nil
			case epi.InType() == uint16(TdhInTypeAnsistring):
				return uint32(epi.Length()), nil
			case epi.InType() == uint16(TdhInTypeSid):
				return uint32(epi.Length()), nil
			case epi.InType() == uint16(TdhInTypeWbemsid):
				return uint32(epi.Length()), nil
			case epi.Flags&PropertyStruct == PropertyStruct:
				return uint32(epi.Length()), nil
			default:
				return 0, fmt.Errorf("unexpected length of 0 for intype %d and outtype %d", epi.InType(), epi.OutType())
			}
		}
	}
}

func (e *EventRecordHelper) GetArraySize(i uint32) (arraySize uint16, err error) {
	dataDesc := PropertyDataDescriptor{}
	propSz := uint32(0)

	epi := e.TraceInfo.GetEventPropertyInfoAt(i)
	if (epi.Flags & PropertyParamCount) == PropertyParamCount {
		count := uint32(0)
		j := epi.CountUnion
		dataDesc.PropertyName = uint64(e.TraceInfo.pointer() + uintptr(e.TraceInfo.GetEventPropertyInfoAt(uint32(j)).NameOffset))
		dataDesc.ArrayIndex = math.MaxUint32
		if err = TdhGetPropertySize(e.Event, 0, nil, 1, &dataDesc, &propSz); err != nil {
			return
		}
		if err = TdhGetProperty(e.Event, 0, nil, 1, &dataDesc, propSz, ((*byte)(unsafe.Pointer(&count)))); err != nil {
			return
		}
		arraySize = uint16(count)
	} else {
		arraySize = epi.CountUnion
	}
	return
}

func (e *EventRecordHelper) ParseProperty(i uint32) (name, value string, err error) {
	var mapInfo *EventMapInfo
	var propertyLength uint32
	var udc uint16
	var buff []uint16

	epi := e.TraceInfo.GetEventPropertyInfoAt(i)
	formattedDataSize := uint32(64)

	// Get the name/value mapping if the property specifies a value map.
	if epi.MapNameOffset() > 0 {
		pMapName := (*uint16)(unsafe.Pointer(e.TraceInfo.pointerOffset(uintptr(epi.MapNameOffset()))))
		if mapInfo, err = e.Event.GetMapInfo(pMapName, uint32(e.TraceInfo.DecodingSource)); err != nil {
			err = fmt.Errorf("failed to get map info: %s", err)
			return
		}
	}

	if propertyLength, err = e.GetPropertyLength(i); err != nil {
		err = fmt.Errorf("failed to get property length: %s", err)
		return
	}

	for {
		buff = make([]uint16, formattedDataSize)

		err = TdhFormatProperty(
			e.TraceInfo,
			mapInfo,
			e.Event.PointerSize(),
			epi.InType(),
			epi.OutType(),
			uint16(propertyLength),
			e.UserDataLength(),
			(*byte)(unsafe.Pointer(e.userDataIt)),
			&formattedDataSize,
			&buff[0],
			&udc)

		if err == syscall.ERROR_INSUFFICIENT_BUFFER {
			continue
		}

		if err == ERROR_EVT_INVALID_EVENT_DATA {
			if mapInfo == nil {
				break
			}
			mapInfo = nil
			continue
		}

		if err == nil {
			break
		}

		err = fmt.Errorf("failed to format property : %s", err)
		break
	}

	name = UTF16AtOffsetToString(e.TraceInfo.pointer(), uintptr(epi.NameOffset))
	value = syscall.UTF16ToString(buff)
	e.userDataIt += uintptr(udc)
	return
}

func (e *EventRecordHelper) ParseExtendedData(i uint16) string {

	item := (*EventHeaderExtendedDataItem)(unsafe.Pointer((uintptr(unsafe.Pointer(e.Event.ExtendedData)) + (uintptr(i) * unsafe.Sizeof(EventHeaderExtendedDataItem{})))))
	switch item.ExtType {
	case EVENT_HEADER_EXT_TYPE_RELATED_ACTIVITYID:
		g := (*GUID)(unsafe.Pointer(item.DataPtr))
		return g.String()
	default:
		return "not parsed"
	}
}

func (e *EventRecordHelper) BuildEventWithMetadata() (event *Event) {
	event = NewEvent()

	event.Event.System.Computer = hostname
	event.Event.System.Execution.ProcessID = e.Event.EventHeader.ProcessId
	event.Event.System.Execution.ThreadID = e.Event.EventHeader.ThreadId
	event.Event.System.EventID = e.TraceInfo.EventID()
	event.Event.System.Channel = e.TraceInfo.ChannelName()
	event.Event.System.Provider.Guid = e.TraceInfo.ProviderGuid.String()
	event.Event.System.Provider.Name = e.TraceInfo.ProviderName()
	event.Event.System.Level.Value = e.TraceInfo.EventDescriptor.Level
	event.Event.System.Level.Name = e.TraceInfo.LevelName()
	event.Event.System.Opcode.Value = e.TraceInfo.EventDescriptor.Opcode
	event.Event.System.Opcode.Name = e.TraceInfo.OpcodeName()
	event.Event.System.Keywords.Value = e.TraceInfo.EventDescriptor.Keyword
	event.Event.System.Keywords.Name = e.TraceInfo.KeywordName()
	event.Event.System.TimeCreated.SystemTime = e.Event.EventHeader.UTCTimeStamp()

	if e.TraceInfo.IsMof() {
		var eventType string
		if t, ok := MofClassMapping[e.TraceInfo.EventGUID.Data1]; ok {
			eventType = fmt.Sprintf("%s/%s", t.Name, event.Event.System.Opcode.Name)
		} else {
			eventType = fmt.Sprintf("UnknownClass/%s", event.Event.System.Opcode.Name)
		}
		event.Event.System.EventType = eventType
		event.Event.System.EventGuid = e.TraceInfo.EventGUID.String()
	}

	return
}

func (e *EventRecordHelper) ParseProperties(event *Event) (err error) {
	var arraySize uint16
	var value, name string

	eventData := event.Event.EventData

	if (e.TraceInfo.Flags & TEMPLATE_USER_DATA) == TEMPLATE_USER_DATA {
		eventData = event.Event.UserData
	}

	for i := uint32(0); i < e.TraceInfo.TopLevelPropertyCount; i++ {
		epi := e.TraceInfo.GetEventPropertyInfoAt(i)
		isArray := epi.Flags&PropertyParamCount == PropertyParamCount
		switch {
		case isArray:
			log.Debugf("Property is an array")
		case epi.Flags&PropertyParamLength == PropertyParamLength:
			log.Debugf("Property is a buffer")
		case epi.Flags&PropertyParamCount == PropertyStruct:
			log.Debugf("Property is a struct")
		default:
			// property is a map
		}

		if arraySize, err = e.GetArraySize(i); err != nil {
			return
		} else {
			var arrayName string
			var array []interface{}

			// this is not because we have arraySize > 0 that we are an array
			// so if we deal with an array property
			if isArray {
				array = make([]interface{}, 0)
			}

			for k := uint16(0); k < arraySize; k++ {
				// If the property is a structure, print the members of the structure.
				if epi.Flags&PropertyStruct == PropertyStruct {
					log.Debugf("structure over here")
					propStruct := make(map[string]interface{})
					lastMember := epi.StructStartIndex() + epi.NumOfStructMembers()
					for j := epi.StructStartIndex(); j < lastMember; j++ {
						log.Debugf("parsing struct property: %d", j)
						if name, value, err = e.ParseProperty(uint32(j)); err != nil {
							return
						} else {
							propStruct[name] = value
						}
					}
					if isArray {
						arrayName = "Structures"
						array = append(array, propStruct)
					}
				} else {
					if name, value, err = e.ParseProperty(i); err != nil {
						return
					} else {
						if isArray {
							arrayName = name
							array = append(array, value)
						} else {
							eventData[name] = value
						}
					}
				}
			}

			if isArray {
				eventData[arrayName] = array
			}
		}
	}

	return
}
