package ipv4opt

import (
	"fmt"
	"net"
)

//OptionType repesents and option.
type OptionType uint8

//SecurityLevel is the security level from a security option.
type SecurityLevel uint16

//SecurityCompartment ...
type SecurityCompartment uint16

//SecurityHandlingRestriction ...
type SecurityHandlingRestriction uint16

//SecurityTCC ...
type SecurityTCC uint32

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
	EndOfOptionList = 0
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
	//ErrIncorrectRRLength is returned when an RR option has route data with a length
	//that is not a multiple of 4.
	ErrIncorrectRRLength = fmt.Errorf("The length of the RR data is not a multiple of 4")
)

type option struct {
	otype  OptionType
	length int
	data   []byte
}

func (o option) Type() OptionType {
	return o.otype
}

func (o option) Length() int {
	return o.length
}

func (o option) Data() []byte {
	return o.data
}

//IPOption is the interface for an IPv4 option.
type IPOption interface {
	Type() OptionType
	Length() int
	Data() []byte
}

//Sec is the ipv4 security option
type Sec struct {
	option
	Level       SecurityLevel
	Compartment SecurityCompartment
	Restriction SecurityHandlingRestriction
	TCC         SecurityTCC
}

const securityOpLen = 11

func parseSecurity(data []byte) (IPOption, error) {
	var so Sec
	so.option.otype = Security
	if len(data) < securityOpLen {
		return nil, fmt.Errorf("security option data too short %v", data)
	}
	so.option.length = securityOpLen
	so.option.data = make([]byte, 11, 11)
	copy(so.option.data, data)

	so.Level |= SecurityLevel(data[2]) << 8

	so.Level |= SecurityLevel(data[3])

	so.Compartment |= SecurityCompartment(data[4]) << 8
	so.Compartment |= SecurityCompartment(data[5])

	so.Restriction |= SecurityHandlingRestriction(data[6]) << 8
	so.Restriction |= SecurityHandlingRestriction(data[7])

	so.TCC |= SecurityTCC(data[6]) << 16
	so.TCC |= SecurityTCC(data[9]) << 8
	so.TCC |= SecurityTCC(data[10])

	return so, nil
}

//RR is an ipv4 record route option
type RR struct {
	option
	Pointer byte
	Routes  []Route
}

func parseRecordRoute(data []byte) (IPOption, error) {
	var rr RR
	rr.option.otype = OptionType(data[0])
	rr.option.length = int(data[1])
	rr.option.data = make([]byte, rr.option.length, rr.option.length)
	copy(rr.option.data, data)

	rr.Pointer = rr.option.data[2]
	if (rr.option.length-3)%4 != 0 {
		return nil, ErrIncorrectRRLength
	}
	var i int
	for i = 3; i < rr.option.length; i += 4 {
		var route Route
		route |= Route(rr.option.data[i]) << 24
		route |= Route(rr.option.data[i+1]) << 16
		route |= Route(rr.option.data[i+2]) << 8
		route |= Route(rr.option.data[i+3])

		rr.Routes = append(rr.Routes, route)
	}
	return rr, nil
}

//StreamID is an ipv4 stream id option
type StreamID struct {
	option
	ID uint16
}

const streamIDOptLen = 4

func parseStreamID(data []byte) (IPOption, error) {
	var sid StreamID
	sid.option.otype = OptionType(data[0])
	sid.option.length = streamIDOptLen
	sid.option.data = make([]byte, streamIDOptLen, streamIDOptLen)
	copy(sid.option.data, data)
	if len(data) < 4 {
		return nil, fmt.Errorf("Not enought data for stream id option")
	}
	sid.ID |= uint16(data[2]) << 8
	sid.ID |= uint16(data[3])

	return sid, nil

}

//Stamp represents a timestamp address pair from a timestamp option
type Stamp struct {
	Time Timestamp
	Addr Address
}

//TS is an IPv4 timestamp option
type TS struct {
	option
	Pointer byte
	Flags   Flag
	Over    Overflow
	Stamps  []Stamp
}

func parseTimeStamp(data []byte) (IPOption, error) {
	var ts TS

	ts.option.otype = OptionType(data[0])
	ts.option.length = int(data[1])
	ts.option.data = make([]byte, ts.option.length, ts.option.length)
	copy(ts.option.data, data)
	ts.Pointer = data[2]
	ts.Over = Overflow(data[3] >> 4)
	ts.Flags = Flag(data[3] & 0x0F)
	var err error
	switch ts.Flags {
	case TSOnly:
		ts.Stamps, err = getStampsTSOnly(data[4:], ts.option.length-4)
		if err != nil {
			return nil, err
		}
	case TSAndAddr, TSPrespec:
		ts.Stamps, err = getStamps(data[4:], ts.option.length-4)
		if err != nil {
			return nil, err
		}
	}
	return ts, nil
}

func getStampsTSOnly(data []byte, length int) ([]Stamp, error) {
	var stamp []Stamp
	var i int
	for i = 0; i < length; i += 4 {
		st := Stamp{}
		st.Time |= Timestamp(data[i]) << 24
		st.Time |= Timestamp(data[i+1]) << 16
		st.Time |= Timestamp(data[i+2]) << 8
		st.Time |= Timestamp(data[i+3])
		stamp = append(stamp, st)
	}
	return stamp, nil
}

func getStamps(data []byte, length int) ([]Stamp, error) {
	var stamp []Stamp
	var i int
	for i = 0; i < length; i += 8 {
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

// NoOp is the NoOperation option
type NoOp struct {
	option
}

func parseNOOP(data []byte) (IPOption, error) {
	var opt NoOp
	if len(data) < 1 {
		return nil, fmt.Errorf("Failed to parse NoOperation, no data available")
	}
	opt.option.length = 1
	opt.option.otype = NoOperation
	opt.option.data = make([]byte, 1, 1)
	copy(opt.option.data, data)
	return opt, nil
}

// EOOList is the EndOfOptionsList option
type EOOList struct {
	option
}

func parseEOOList(data []byte) (IPOption, error) {
	var opt EOOList
	if len(data) < 1 {
		return nil, fmt.Errorf("Failed to parse NoOperation, no data available")
	}
	opt.option.length = 1
	opt.option.otype = NoOperation
	opt.option.data = make([]byte, 1, 1)
	copy(opt.option.data, data)
	return opt, nil
}

type parseFunc func([]byte) (IPOption, error)

var parsers = map[OptionType]parseFunc{
	EndOfOptionList:         parseEOOList,
	NoOperation:             parseNOOP,
	Security:                parseSecurity,
	LooseSourceRecordRoute:  parseRecordRoute,
	StrictSourceRecordRoute: parseRecordRoute,
	RecordRoute:             parseRecordRoute,
	StreamIdentifier:        parseStreamID,
	InternetTimestamp:       parseTimeStamp,
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
	var i int
	for i = 0; i < optsLen; {
		oType, err := getOptionType(opts[i])
		if err != nil {
			return nil, err
		}
		o, err := parsers[oType](opts[i:])
		if err != nil {
			return nil, err
		}
		options = append(options, o)
		i += o.Length()
	}
	return options, nil

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
		return EndOfOptionList, ErrOptionType
	}
}
