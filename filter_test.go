package ipfix

import (
	"math/rand"
	"testing"
)

func TestBitmaskFilter(t *testing.T) {
	var bm uint16Bitmask

	bm.set(0)
	if !bm.isset(0) {
		t.Fatalf("Failed to set")
	}
	bm.clear(0)
	if bm.isset(0) {
		t.Fatalf("Failed to clear")
	}

	//make sure nothing is set
	for i := 0; i < 0x10000; i++ {
		if bm.isset(uint16(i)) {
			t.Fatalf("bit %d is set", i)
		}
	}

	//set everything
	for i := 0; i < 0x10000; i++ {
		bm.set(uint16(i))
	}

	//make sure everything is set
	for i := 0; i < 0x10000; i++ {
		if !bm.isset(uint16(i)) {
			t.Fatalf("%d is not set", i)
		}
	}

	//clear everything
	for i := 0; i < 0x10000; i++ {
		bm.clear(uint16(i))
	}

	//make sure nothing is set
	for i := 0; i < 0x10000; i++ {
		if bm.isset(uint16(i)) {
			t.Fatalf("bit %d is set", i)
		}
	}

	//randomly set a bunch of shit
	hits := make([]int, 0, 100)
	for i := 0; i < cap(hits); i++ {
		v := rand.Intn(0x10000)
		bm.set(uint16(v))
		if !bm.isset(uint16(v)) {
			t.Fatalf("Failed to set %d", i)
		}
		hits = append(hits, v)
	}

	//check that ONLY the items in hits are set
	for i := 0; i < 0x10000; i++ {
		if bm.isset(uint16(i)) != contains(hits, i) {
			t.Fatalf("Bad status on %d: %v != %v", i, bm.isset(uint16(i)), contains(hits, i))
		}
	}
}

func TestFilter(t *testing.T) {
	tset := []otherFilter{
		otherFilter{},
	}
addloop:
	for i := 0; i < 50; i++ {
		eid := rand.Uint32()
		for x := range tset {
			if tset[x].eid == eid {
				continue addloop
			}
		}
		tset = append(tset, otherFilter{eid: eid})
	}
	var f Filter
	for j := range tset {
		for i := 0; i < 100; i++ {
			v := rand.Intn(0x10000)
			tset[j].set(uint16(v))
			f.Set(tset[j].eid, uint16(v))
		}
	}
	if len(tset) != (len(f.others) + 1) {
		t.Fatalf("invalid filter other set count: %d != %d", len(tset), (len(f.others) + 1))
	}

	for j := range tset {
		for i := 0; i < 0x10000; i++ {
			if tset[j].isset(uint16(i)) != f.IsSet(tset[j].eid, uint16(i)) {
				t.Fatalf("EID %d : %d mismatch -> %v != %v", tset[j].eid,
					i, tset[j].isset(uint16(i)), f.IsSet(tset[j].eid, uint16(i)))
			}
		}
	}
}

func BenchmarkBitmaskFilterSet(b *testing.B) {
	var bm uint16Bitmask
	v := uint16(rand.Intn(0x10000))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		bm.set(v)
	}
}

func BenchmarkBitmaskFilterTest(b *testing.B) {
	var bm uint16Bitmask
	v := uint16(rand.Intn(0x10000))
	bm.set(v)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if !bm.isset(v) {
			b.Fatal("Bad result")
		}
	}
}

func BenchmarkFilterTest(b *testing.B) {
	var f Filter
	v1 := uint16(rand.Intn(0x10000))
	v2 := uint16(rand.Intn(0x10000))
	eid := rand.Uint32()
	f.Set(0, v1)
	f.Set(eid, v2)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if !f.IsSet(0, v1) || !f.IsSet(eid, v2) {
			b.Fatal("Bad result")
		}
	}
}

func contains(set []int, v int) bool {
	for i := range set {
		if set[i] == v {
			return true
		}
	}
	return false
}
