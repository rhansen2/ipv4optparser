package ipv4opt

import (
	"fmt"
	"net"
)

//OptionType repesents and option.
type OptionType uint8

//OptionLength is the length of an option.
type OptionLength uint8

//SecurityLevel is the security level from a security option.
type SecurityLevel uint16

//SecurityCompartment ...
type SecurityCompartment uint16

//SecurityHandlingRestriction ...
type SecurityHandlingRestriction uint16

//SecurityTCC ...
type SecurityTCC uint32

//StreamID is the stream id.
type StreamID uint16

//Timestamp is a timestamp specified in an IP timestamp option.
type Timestamp uint32

//Flag is flag from an option
type Flag uint8

// Overflow is an overflow from a timestamp option.
type Overflow uint8

//Address is an IPv4 address.
type Address uint32

func (addr Address) String() string {
	var a, b, c, d byte
	fmt.
		a = byte(addr >> 24)
	b = byte((addr & 0x00ff0000) >> 16)
	c = byte((addr & 0x0000ff00) >> 8)
	d = byte(addr & 0x000000ff)
	return net.IPv4(a, b, c, d).String()
}

//Route is a recored address in a record route.
type Route uint32

func (r Route) String() string {
	return Address(r).String()
}

const (
	//EndOfOptionList indicates the end of the option list. This is used at the
	// end of all options.
	EndOfOptionList OptionType = 0
	//NoOperation is used between options.
	NoOperation = 1
	//Security provides a way for hosts to send security compartmentation.
	Security = 130
	//LooseSourceRecordRoute provides a means for the sources of an
	//internet datagram to supply routing information to be used in the
	//gateways in forwarding the datagram to the destination, and to
	//record the route information.
	LooseSourceRecordRoute = 131
	//StrictSourceRecordRoute provides a means for the source of an internet
	//datagram to supply routing information to be used by the gateways
	//in forwardig the datagram to the destination, and to record the route information.
	StrictSourceRecordRoute = 137
	//RecordRoute provides a means to record the route of an internet datagram.
	RecordRoute = 7
	//StreamIdentifier provides a way for the 16-bit SATNET stream identifier
	//to be carried through networks that do not support the stream concept.
	StreamIdentifier = 136
	//InternetTimestamp records timestamps along the path of the datagram.
	InternetTimestamp = 68
	//MaxOptionsLen is the maximum length of an IPv4 option section.
	MaxOptionsLen int = 40 // 60 Byte maximum size - 20 bytes for manditory fields

	//Unclassified security level.
	Unclassified SecurityLevel = 0x0
	//Confidential security level.
	Confidential = 0xF135
	//EFTO security level.
	EFTO = 0x789A
	//MMMM security level.
	MMMM = 0xBC4D
	// PROG security level.
	PROG = 0x5E26
	// Restricted security level.
	Restricted = 0xAF13
	// Secret security level.
	Secret = 0xD788
	// TopSecret security level
	TopSecret = 0x6BC5
	//Reserved0 (reserved for future use).
	Reserved0 = 0x35E2
	//Reserved1 (reserved for future use).
	Reserved1 = 0x9AF1
	//Reserved2 (reserved for future use).
	Reserved2 = 0x4D78
	//Reserved3 (reserved for future use).
	Reserved3 = 0x24BD
	//Reserved4 (reserved for future use).
	Reserved4 = 0x135E
	//Reserved5 (reserved for future use).
	Reserved5 = 0x89AF
	//Reserved6 (reserved for future use).
	Reserved6 = 0xC4D6
	//Reserved7 (reserved for future use).
	Reserved7 = 0xE26B
)

const (
	//TSOnly specifies that only timestamps should be included in the
	//timestamp option.
	TSOnly = 0
	//TSAndAddr specifies that each timestamp is preceded with the ip
	//address of the registering entity.
	TSAndAddr = 1
	//TSPrespec specifies that the ip address fields are prespecified.
	TSPrespec = 3
)

var (
	//ErrOptionDataTooLarge is returned when the length of the option data is
	//greater than the maximum option size.
	ErrOptionDataTooLarge = fmt.Errorf("The length of the options data is larger than the max options length")
	//ErrOptionType is returned when an invalid option type is found.
	ErrOptionType = fmt.Errorf("Invalid option type")
	//ErrNegativeOptionLength is returned when the option length is negative.
	ErrNegativeOptionLength = fmt.Errorf("Negative option length")
	//ErrNotEnoughData is returned when there is not enough data left to fulfill the option.
	ErrNotEnoughData = fmt.Errorf("Not enough data left to parse option")
	//ErrInvalidLength is returned when the option length is not appropriate for
	//specified option.
	ErrInvalidLength = fmt.Errorf("The option length is incorrect")
	//ErrRouteLengthIncorrect is returned when the length of a record route option is not
	//a multiple of the address length.
	ErrRouteLengthIncorrect = fmt.Errorf("The length of the route data is not a multiple of 4")
	//ErrTSLengthIncorrect is returned when the length of a timestamp option is not
	//a multiple of the address length.
	ErrTSLengthIncorrect = fmt.Errorf("The length of the route data is not a multiple of 4")
	//ErrStreamIDLengthIncorrect is returned when the length of the streamid is not correct.
	ErrStreamIDLengthIncorrect = fmt.Errorf("Then stream ID length is not 4")
)

type option struct {
	otype  OptionType
	length OptionLength
	data   []byte
}

func (o option) Type() OptionType {
	return o.otype
}

//IPOption is the interface for an IPv4 option.
type IPOption interface {
	Type() OptionType
	Length() OptionLength
	Data() []byte
}

//SecurityOption is the ipv4 security option
type SecurityOption struct {
	o           option
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

//RecordRouteOption is an ipv4 record route option
type RecordRouteOption struct {
	o       option
	Pointer byte
	Routes  []Route
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
	rro.Pointer = byte(o.Data[0])
	for i := 1; i < int(routeLen); i += 4 {
		var route Route
		route |= Route(o.Data[i]) << 24
		route |= Route(o.Data[i+1]) << 16
		route |= Route(o.Data[i+2]) << 8
		route |= Route(o.Data[i+3])

		rro.Routes = append(rro.Routes, route)
	}
	return rro, nil
}

//StreamIdentifierOption is an ipv4 stream id option
type StreamIdentifierOption struct {
	o  option
	ID StreamID
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

//Stamp represents a timestamp address pair from a timestamp option
type Stamp struct {
	Time Timestamp
	Addr Address
}

//TimeStampOption is an IPv4 timestamp option
type TimeStampOption struct {
	o       option
	Pointer byte
	Flags   Flag
	Over    Overflow
	Stamps  []Stamp
}

func (o Option) ToTimeStamp() (TimeStampOption, error) {
	ts := TimeStampOption{}
	ts.Type = o.Type
	ts.Length = o.Length
	if o.Type != InternetTimestamp {
		return ts, ErrorOptionTypeMismatch
	}
	if len(o.Data) > MaxOptionsLen {
		return ts, ErrOptionDataTooLarge
	}
	ts.Pointer = byte(o.Data[0])
	ts.Over = Overflow(o.Data[1] >> 4)
	ts.Flags = Flag(o.Data[1] & 0x0F)
	// Take off two because of the flag and overflow byte and the ponter byte
	if len(o.Data)%4-2 != 0 && ts.Flags != TSOnly {
		return ts, ErrorTSLengthIncorrect
	}
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
	var stamp []Stamp
	for i := 0; i < length; i += 4 {
		st := Stamp{}
		st.Time |= Timestamp(data[i]) << 24
		st.Time |= Timestamp(data[i+1]) << 16
		st.Time |= Timestamp(data[i+2]) << 8
		st.Time |= Timestamp(data[i+3])
		stamp = append(stamp, st)
	}
	return stamp, nil
}

func getStamps(data []OptionData, length int) ([]Stamp, error) {
	var stamp []Stamp
	for i := 0; i < length; i += 8 {
		st := Stamp{}
		st.Addr |= Address(data[i]) << 24
		st.Addr |= Address(data[i+1]) << 16
		st.Addr |= Address(data[i+2]) << 8
		st.Addr |= Address(data[i+3])
		st.Time |= Timestamp(data[i+4]) << 24
		st.Time |= Timestamp(data[i+5]) << 16
		st.Time |= Timestamp(data[i+6]) << 8
		st.Time |= Timestamp(data[i+7])
		stamp = append(stamp, st)
	}
	return stamp, nil
}

// Options is a list of IPv4 Options.
type Options []IPOption

//Parse parses opts into IPv4 options.
func Parse(opts []byte) (Options, error) {
	optsLen := len(opts)
	var options Options
	if optsLen > MaxOptionsLen {
		return nil, ErrOptionDataTooLarge
	}
	if optsLen == 0 {
		return options, nil
	}
	for i := 0; i < optsLen; {
		var opt option
		oType, err := getOptionType(opts[i])
		if err != nil {
			return nil, err
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
		return []OptionData{}, 0, 0, ErrorNegativeOptionLength
	}
	ol := OptionLength(l)
	// Length includes the length byte and type byte so read l - 2 more bytes
	rem := int(l) - 2
	if rem > len(opts)-1 { // If the remaining data is longer than the length of the options data - 1 for length byte
		return []OptionData{}, 0, 0, ErrorNotEnoughData
	}
	// Add one to rem because the synax is [x:)
	dataBytes := opts[1 : rem+1]
	dbl := len(dataBytes)
	ods := make([]OptionData, 0)
	for i := 0; i < dbl; i++ {
		ods = append(ods, OptionData(dataBytes[i]))
	}
	return ods, ol, int(l), nil
}

func getOptionType(b byte) (OptionType, error) {
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
