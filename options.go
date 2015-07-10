package ipv4opt

import (
	"fmt"
)

type OptionType uint8
type OptionLength uint8
type RouteAddress uint32
type OptionData uint8
type SecurityLevel uint16
type SecurityCompartments uint16
type SecurityHandlingRestrictions uint16
type SecurityTCC uint32

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

var (
	ErrorOptionDataTooLarge   = fmt.Errorf("The length of the options data is larger than the max options length")
	ErrorOptionType           = fmt.Errorf("Invalid option type")
	ErrorNegativeOptionLength = fmt.Errorf("Negative option length")
	ErrorNotEnoughData        = fmt.Errorf("Not enough data left to parse option")
	ErrorOptionTypeMismatch   = fmt.Errorf("Tried to convert an option to the wrong type")
)

type Option struct {
	Type   OptionType
	Length OptionLength
	Data   []OptionData
}

type Options []Option

type SecurityOption struct {
}

func (o Option) ToSecurity() (SecurityOption, error) {
	if o.Type != Security {
		return SecurityOption{}, ErrorOptionTypeMismatch
	}
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
	rem := int(l) - 2      // Length includes the length byte and type byte so read l - 2 more bytes
	if rem > len(opts)-1 { // If the remaining data is longer than the length of the options data - 1 for length byte
		return []OptionData{}, 0, 0, ErrorNegativeOptionLength
	}
	dataBytes := opts[2:rem]
	ods := make([]OptionData, 0)
	for i := 0; i < rem; i++ {
		ods = append(ods, OptionData(dataBytes[i]))
	}
	return ods, ol, rem, nil
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
