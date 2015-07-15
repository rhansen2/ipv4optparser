package ipv4opt_test

import (
	"github.com/rhansen2/ipv4optparser"
	"testing"
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
	50, 2, 208, 113, 237,
}

func TestParse(t *testing.T) {
	_, err := ipv4opt.Parse(rrTest)
	if err != nil {
		t.Fatal(err)
	}
}

func TestToRecordRoute(t *testing.T) {
	ops, err := ipv4opt.Parse(rrTest)
	if err != nil {
		t.Fatal(err)
	}
	rropt := ops[0]
	if rropt.Type != ipv4opt.RecordRoute {
		t.Fatal("Failed to parse RR out of RR option")
	}
	_, err = rropt.ToRecordRoute()
	if err != nil {
		t.Fatal(err)
	}
}

func TestToTimestamp(t *testing.T) {
	ops, err := ipv4opt.Parse(tsTest)
	if err != nil {
		t.Fatal(err)
	}
	tsopt := ops[0]
	if tsopt.Type != ipv4opt.InternetTimestamp {
		t.Fatal("Failed to parse TS out of TS option")
	}
	_, err = tsopt.ToTimeStamp()
	if err != nil {
		t.Fatal(err)
	}
}

func TestToTimestampTwo(t *testing.T) {
	ops, err := ipv4opt.Parse(tsTest2)
	if err != nil {
		t.Fatal(err)
	}
	tsopt := ops[0]
	if tsopt.Type != ipv4opt.InternetTimestamp {
		t.Fatal("Failed to parse TS out of TS option")
	}
	_, err = tsopt.ToTimeStamp()
	if err != nil {
		t.Fatal(err)
	}
}

func TestToTimestampPreSpec(t *testing.T) {
	ops, err := ipv4opt.Parse(tsPreSpec)
	if err != nil {
		t.Fatal(err)
	}
	tsopt := ops[0]
	if tsopt.Type != ipv4opt.InternetTimestamp {
		t.Fatal("Failed to parse TS out of TS options")
	}
	ts, err := tsopt.ToTimeStamp()
	if err != nil {
		t.Fatal(err)
	}
	stamp := ts.Stamps[0]
	if stamp.Addr != 1114449458 {
		t.Fatal("Wrong IP found in prespec")
	}
}
