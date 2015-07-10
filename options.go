package ipv4opt

import (
	"fmt"
)

type OptionType uint8
type OptionLength uint8
type RouteAddress uint32
type OptionData uint8
type SecurityLevel uint16

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
)

type Option struct {
	Type   OptionType
	Length OptionLength
	Data   []OptionData
}

type Options []Option

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

	}
	return Options{}, nil

}

type optParser func([]byte) (OptionData, OptionLength, error)

var parsers = map[OptionType]optParser{Security: parseSecurity}

func parseOption(opts []byte, oType OptionType) (OptionData, OptionLength, error) {
	switch oType {
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

func parseSecurity(odata []byte) (OptionData, OptionLength, error) {
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
