package ipv4opt

import (
	"fmt"
)

type OptionType uint8
type OptionLength uint8
type RouteAddress uint32
type OptionData uint8
type SecurityLevel uint16
type SecurityCompartment uint16
type SecurityHandlingRestriction uint16
type SecurityTCC uint32
type Route uint32
type StreamID uint16
type Timestamp uint32
type Flag uint8
type Overflow uint8
type Address uint32

const (
	EndOfOptionList         OptionType = 0
	NoOperation                        = 1
	Security                           = 130
	LooseSourceRecordRoute             = 131
	StrictSourceRecordRoute            = 137
	RecordRoute                        = 7
	StreamIdentifier                   = 136
	InternetTimestamp                  = 68
	MaxOptionsLen           int        = 40 // 60 Byte maximum size - 20 bytes for manditory fields

	Unclassified SecurityLevel = 0x0
	Confidential               = 0xF135
	EFTO                       = 0x789A
	MMMM                       = 0xBC4D
	PROG                       = 0x5E26
	Restricted                 = 0xAF13
	Secret                     = 0xD788
	TopSecret                  = 0x6BC5
	Reserved0                  = 0x35E2
	Reserved1                  = 0x9AF1
	Reserved2                  = 0x4D78
	Reserved3                  = 0x24BD
	Reserved4                  = 0x135E
	Reserved5                  = 0x89AF
	Reserved6                  = 0xC4D6
	Reserved7                  = 0xE26B
)

const (
	TSOnly = iota + 1
	TSAndAddr
	TSPrespec
)

var (
	ErrorOptionDataTooLarge      = fmt.Errorf("The length of the options data is larger than the max options length")
	ErrorOptionType              = fmt.Errorf("Invalid option type")
	ErrorNegativeOptionLength    = fmt.Errorf("Negative option length")
	ErrorNotEnoughData           = fmt.Errorf("Not enough data left to parse option")
	ErrorOptionTypeMismatch      = fmt.Errorf("Tried to convert an option to the wrong type")
	ErrorInvalidLength           = fmt.Errorf("The option length is incorrect")
	ErrorRouteLengthIncorrect    = fmt.Errorf("The length of the route data is not a multiple of 4")
	ErrorTSLengthIncorrect       = fmt.Errorf("The length of the route data is not a multiple of 4")
	ErrorStreamIDLengthIncorrect = fmt.Errorf("Then stream ID length is not 4")
)

type Option struct {
	Type   OptionType
	Length OptionLength
	Data   []OptionData
}

type Options []Option

type SecurityOption struct {
	Type        OptionType
	Length      OptionLength
	Level       SecurityLevel
	Compartment SecurityCompartment
	Restriction SecurityHandlingRestriction
	TCC         SecurityTCC
}

func (o Option) ToSecurity() (SecurityOption, error) {
	so := SecurityOption{}
	so.Type = o.Type
	so.Length = o.Length
	if o.Type != Security {
		return so, ErrorOptionTypeMismatch
	}
	if o.Length != 11 {
		return so, ErrorInvalidLength
	}
	data := o.Data
	so.Level |= SecurityLevel(data[0]) << 8
	so.Level |= SecurityLevel(data[1])

	so.Compartment |= SecurityCompartment(data[2]) << 8
	so.Compartment |= SecurityCompartment(data[3])

	so.Restriction |= SecurityHandlingRestriction(data[4]) << 8
	so.Restriction |= SecurityHandlingRestriction(data[5])

	so.TCC |= SecurityTCC(data[6]) << 16
	so.TCC |= SecurityTCC(data[7]) << 8
	so.TCC |= SecurityTCC(data[8])

	return so, nil
}

type RecordRouteOption struct {
	Type   OptionType
	Length OptionLength
	Routes []Route
}

func (o Option) ToRecordRoute() (RecordRouteOption, error) {
	rro := RecordRouteOption{}
	rro.Type = o.Type
	rro.Length = o.Length
	if o.Type != StrictSourceRecordRoute &&
		o.Type != LooseSourceRecordRoute &&
		o.Type != RecordRoute {
		return rro, ErrorOptionTypeMismatch
	}
	routeLen := rro.Length - 3 // The length of routes is length - 3 because length include the pointer type and length
	if routeLen%4 != 0 {
		return rro, ErrorRouteLengthIncorrect
	}
	for i := 1; i < int(routeLen); i += 4 {
		//Start at i = 1 Because the first byte following the lenght byte is the pointer and we don't need that
		var route Route
		route |= Route(o.Data[i]) << 24
		route |= Route(o.Data[i+1]) << 16
		route |= Route(o.Data[i+2]) << 8
		route |= Route(o.Data[i+3])

		rro.Routes = append(rro.Routes, route)
	}
	return rro, nil
}

type StreamIdentifierOption struct {
	Type   OptionType
	Length OptionLength
	ID     StreamID
}

func (o Option) ToStreamID() (StreamIdentifierOption, error) {
	sid := StreamIdentifierOption{}
	sid.Type = o.Type
	sid.Length = o.Length
	if o.Type != StreamIdentifier {
		return sid, ErrorOptionTypeMismatch
	}
	if o.Length != 4 {
		return sid, ErrorStreamIDLengthIncorrect
	}
	sid.ID |= StreamID(o.Data[0]) << 8
	sid.ID |= StreamID(o.Data[1])

	return sid, nil

}

type Stamp struct {
	Time Timestamp
	Addr Address
}

type TimeStampOption struct {
	Type   OptionType
	Length OptionLength
	Flags  Flag
	Over   Overflow
	Stamps []Stamp
}

func (o Option) ToTimeStamp() (TimeStampOption, error) {
	ts := TimeStampOption{}
	ts.Type = o.Type
	ts.Length = o.Length
	if o.Type != InternetTimestamp {
		return ts, ErrorOptionTypeMismatch
	}
	if len(o.Data) > MaxOptionsLen {
		return ts, ErrorOptionDataTooLarge
	}
	if len(o.Data)-2%4 != 0 {
		return ts, ErrorTSLengthIncorrect
	}

	ts.Over = Overflow(o.Data[1] >> 4)
	ts.Flags = Flag(o.Data[1] & 0x0F)
	var err error
	switch ts.Flags {
	case TSOnly:
		ts.Stamps, err = getStampsTSOnly(o.Data[2:], len(o.Data)-2)
		if err != nil {
			return ts, err
		}
	case TSAndAddr, TSPrespec:
		ts.Stamps, err = getStamps(o.Data[2:], len(o.Data)-2)
		if err != nil {
			return ts, err
		}
	}
	return ts, nil
}

func getStampsTSOnly(data []OptionData, length int) ([]Stamp, error) {
	stamp := make([]Stamp, 0)
	for i := 0; i < length; i += 4 {
		st := Stamp{}
		st.Time |= Timestamp(data[i] << 24)
		st.Time |= Timestamp(data[i+1] << 16)
		st.Time |= Timestamp(data[i+2] << 8)
		st.Time |= Timestamp(data[i+3])
		stamp = append(stamp, st)
	}
	return stamp, nil
}

func getStamps(data []OptionData, length int) ([]Stamp, error) {
	stamp := make([]Stamp, 0)
	for i := 0; i < length; i += 8 {
		st := Stamp{}
		st.Time |= Timestamp(data[i] << 24)
		st.Time |= Timestamp(data[i+1] << 16)
		st.Time |= Timestamp(data[i+2] << 8)
		st.Time |= Timestamp(data[i+3])
		st.Addr |= Address(data[i+4] << 24)
		st.Addr |= Address(data[i+5] << 16)
		st.Addr |= Address(data[i+6] << 8)
		st.Addr |= Address(data[i+7])
		stamp = append(stamp, st)
	}
	return stamp, nil
}

func Parse(opts []byte) (Options, error) {
	optsLen := len(opts)
	if optsLen > MaxOptionsLen {
		return Options{}, ErrorOptionDataTooLarge
	}
	if optsLen == 0 {
		return Options{}, nil
	}
	options := make(Options, 0)
	for i := 0; i < optsLen; {
		option := Option{}
		oType, err := getOptionType(opts[i])
		if err != nil {
			return options, err
		}
		i++
		option.Type = oType
		if oType == EndOfOptionList {
			return append(options, option), nil
		}
		if oType == NoOperation {
			options = append(options, option)
			continue
		}
		data, l, n, err := parseOption(opts[i:])
		if err != nil {
			return Options{}, err
		}
		i += n
		option.Length = l
		option.Data = data
		options = append(options, option)
	}
	return options, nil

}

func parseOption(opts []byte) ([]OptionData, OptionLength, int, error) {
	l := opts[0]
	if l < 0 {
		return []OptionData{}, 0, 0, ErrorNotEnoughData
	}
	ol := OptionLength(l)
	// Length includes the length byte and type byte so read l - 2 more bytes
	// but the option type is removed so only l - 1
	rem := int(l) - 1
	if rem > len(opts)-1 { // If the remaining data is longer than the length of the options data - 1 for length byte
		return []OptionData{}, 0, 0, ErrorNegativeOptionLength
	}
	dataBytes := opts[2:rem]
	dbl := len(dataBytes)
	ods := make([]OptionData, 0)
	for i := 0; i < dbl; i++ {
		ods = append(ods, OptionData(dataBytes[i]))
	}
	return ods, ol, rem, nil
}

func getOptionType(b byte) (OptionType, error) {
	fmt.Println(b)
	switch OptionType(b) {
	case EndOfOptionList:
		return EndOfOptionList, nil
	case NoOperation:
		return NoOperation, nil
	case Security:
		return Security, nil
	case LooseSourceRecordRoute:
		return LooseSourceRecordRoute, nil
	case StrictSourceRecordRoute:
		return StrictSourceRecordRoute, nil
	case RecordRoute:
		return RecordRoute, nil
	case StreamIdentifier:
		return StreamIdentifier, nil
	case InternetTimestamp:
		return InternetTimestamp, nil
	default:
		//Just return EndOfOptionList to satisfy return
		return EndOfOptionList, ErrorOptionType
	}
}
