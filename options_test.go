package ipv4opt_test

import (
	"reflect"
	"testing"

	"github.com/rhansen2/ipv4optparser"
)

var rrTest = []byte{
	7, 39, 40, 137, 165, 1, 25, 66, 109, 38,
	50, 66, 109, 52, 166, 66, 109, 52, 165,
	198, 32, 160, 59, 109, 105, 96, 13, 109,
	105, 102, 45, 10, 32, 67, 205, 10, 32, 67,
	218, 0,
}

var tsTest = []byte{
	68, 40, 41, 64, 3, 238, 171, 55, 3, 238,
	171, 49, 3, 238, 171, 44, 3, 238, 171, 44,
	3, 238, 171, 46, 3, 238, 171, 48, 3, 238,
	171, 130, 3, 238, 171, 118, 3, 238, 171, 118,
}

var tsTest2 = []byte{
	68, 36, 37, 97, 137, 165, 1, 25, 4, 67,
	3, 108, 66, 109, 38, 50, 4, 67, 3, 101,
	66, 109, 52, 166, 4, 67, 3, 93, 66, 109,
	52, 165, 4, 67, 3, 93,
}

var tsPreSpec = []byte{
	68, 12, 13, 67, 66, 109, 38,
	50, 2, 208, 113, 237, 0,
}

func TestParse(t *testing.T) {
	_, err := ipv4opt.Parse(rrTest)
	if err != nil {
		t.Fatal(err)
	}
}

func TestRecordRoute(t *testing.T) {
	for _, test := range []struct {
		testData []byte
		data     []byte
		oType    ipv4opt.OptionType
		len      int
		pointer  byte
		routes   []ipv4opt.Route
	}{
		{
			oType:    ipv4opt.RecordRoute,
			len:      39,
			testData: rrTest,
			data: []byte{
				7, 39, 40, 137, 165, 1, 25, 66, 109, 38,
				50, 66, 109, 52, 166, 66, 109, 52, 165,
				198, 32, 160, 59, 109, 105, 96, 13, 109,
				105, 102, 45, 10, 32, 67, 205, 10, 32, 67, 218,
			},
			pointer: 40,
			routes: []ipv4opt.Route{
				2309292313,
				1114449458,
				1114453158,
				1114453157,
				3324026939,
				1835622413,
				1835623981,
				169886669,
				169886682,
			},
		},
	} {
		ops, err := ipv4opt.Parse(test.testData)
		if err != nil {
			t.Fatalf("Failed to parse test data: %v", err)
		}
		opt := ops[0]
		if opt.Type() != test.oType {
			t.Fatalf("Incorrect Option type, Expected(%v), Got(%v)", test.oType, opt.Type())
		}
		if opt.Length() != test.len {
			t.Fatalf("Incorrect option len, Expected(%v), Got(%v)", test.len, opt.Length())
		}
		if !reflect.DeepEqual(opt.Data(), test.data) {
			t.Fatalf("Wrong data in option, Expected(%v), Got(%v)", test.data, opt.Data())
		}
		rro := opt.(ipv4opt.RR)
		if rro.Pointer != test.pointer {
			t.Fatalf("Wrong pointer, Expected(%v), Got(%v)", test.pointer, rro.Pointer)
		}
		if !reflect.DeepEqual(rro.Routes, test.routes) {
			t.Fatalf("Wrong route, Expected(%v), Got(%v)", test.routes, rro.Routes)
		}
	}
}

func compareStamps(l, r []ipv4opt.Stamp, t *testing.T) bool {
	if len(l) != len(r) {
		return false
	}
	for i, li := range l {
		if li != r[i] {
			t.Logf("%v is not equal to %v", li, r[i])
			return false
		}
	}
	return true
}

func TestTimestamp(t *testing.T) {
	for _, test := range []struct {
		testData []byte
		data     []byte
		oType    ipv4opt.OptionType
		len      int
		pointer  byte
		flag     ipv4opt.Flag
		over     ipv4opt.Overflow
		stamps   []ipv4opt.Stamp
	}{
		{
			testData: tsTest,
			data: []byte{
				68, 40, 41, 64, 3, 238, 171, 55, 3, 238,
				171, 49, 3, 238, 171, 44, 3, 238, 171, 44,
				3, 238, 171, 46, 3, 238, 171, 48, 3, 238,
				171, 130, 3, 238, 171, 118, 3, 238, 171, 118,
			},
			oType:   ipv4opt.InternetTimestamp,
			len:     40,
			pointer: 41,
			flag:    ipv4opt.TSOnly,
			over:    ipv4opt.Overflow(4),
			stamps: []ipv4opt.Stamp{
				ipv4opt.Stamp{
					Time: 65973047,
				},
				ipv4opt.Stamp{
					Time: 65973041,
				},
				ipv4opt.Stamp{
					Time: 65973036,
				},
				ipv4opt.Stamp{
					Time: 65973036,
				},
				ipv4opt.Stamp{
					Time: 65973038,
				},
				ipv4opt.Stamp{
					Time: 65973040,
				},
				ipv4opt.Stamp{
					Time: 65973122,
				},
				ipv4opt.Stamp{
					Time: 65973110,
				},
				ipv4opt.Stamp{
					Time: 65973110,
				},
			},
		},
		{
			testData: tsTest2,
			data: []byte{
				68, 36, 37, 97, 137, 165, 1, 25, 4, 67,
				3, 108, 66, 109, 38, 50, 4, 67, 3, 101,
				66, 109, 52, 166, 4, 67, 3, 93, 66, 109,
				52, 165, 4, 67, 3, 93,
			},
			oType:   ipv4opt.InternetTimestamp,
			len:     36,
			pointer: 37,
			flag:    ipv4opt.TSAndAddr,
			over:    ipv4opt.Overflow(6),
			stamps: []ipv4opt.Stamp{
				ipv4opt.Stamp{
					Addr: 2309292313,
					Time: 71500652,
				},
				ipv4opt.Stamp{
					Addr: 1114449458,
					Time: 71500645,
				},
				ipv4opt.Stamp{
					Addr: 1114453158,
					Time: 71500637,
				},
				ipv4opt.Stamp{
					Addr: 1114453157,
					Time: 71500637,
				},
			},
		},
		{
			testData: tsPreSpec,
			data: []byte{
				68, 12, 13, 67, 66, 109, 38,
				50, 2, 208, 113, 237,
			},
			oType:   ipv4opt.InternetTimestamp,
			len:     12,
			pointer: 13,
			flag:    ipv4opt.TSPrespec,
			over:    ipv4opt.Overflow(4),
			stamps: []ipv4opt.Stamp{
				ipv4opt.Stamp{
					Time: 47215085,
					Addr: 1114449458,
				},
			},
		},
	} {
		ops, err := ipv4opt.Parse(test.testData)
		if err != nil {
			t.Fatalf("Failed to parse test data: %v", err)
		}
		opt := ops[0]
		if opt.Type() != test.oType {
			t.Fatalf("Incorrect Option type, Expected(%v), Got(%v)", test.oType, opt.Type())
		}
		if opt.Length() != test.len {
			t.Fatalf("Incorrect option len, Expected(%v), Got(%v)", test.len, opt.Length())
		}
		if !reflect.DeepEqual(opt.Data(), test.data) {
			t.Fatalf("Wrong data in option, Expected(%v), Got(%v)", test.data, opt.Data())
		}
		tso := opt.(ipv4opt.TS)
		if tso.Pointer != test.pointer {
			t.Fatalf("Wrong pointer, Expected(%v), Got(%v)", test.pointer, tso.Pointer)
		}
		if tso.Flags != test.flag {
			t.Fatalf("Wrong flag, Expected(%v), Got(%v)", test.flag, tso.Flags)
		}
		if tso.Over != test.over {
			t.Fatalf("Wrong overflow, Expected(%v), Got(%v)", test.over, tso.Over)
		}
		if !compareStamps(tso.Stamps, test.stamps, t) {
			t.Fatalf("Wrong stamps, Expected(%v), Got(%v)", test.stamps, tso.Stamps)
		}
	}
}
