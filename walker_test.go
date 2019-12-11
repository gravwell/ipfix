package ipfix

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"
)

type cbval struct {
	eid  uint32
	fid  uint16
	data []byte
}

var (
	walkerPkt     []byte
	totalItems    = (15*14 + 16*1 + 15*1 + 16*2 + 15*2 + 16*1 + 15*4) //total number of items in the packet
	filteredItems = (14*2 + 2 + 2 + 4 + 4 + 2 + 8)                    //only looking at source and dest items
)

func init() {
	//fairly simple ipfix flow record with template in the packet
	walkerPkt, _ = hex.DecodeString("000a05785df00ac2000000d200000000000200440103000f00080004000c0004000f000400070002000b000200060001000a0002000e000200020004000100040098000800990008000400010005000100880001010302a47f0000017f00000100000000b59f080700ffff000100000004000012080000016ef1a9ae8d0000016ef1a9aef51100017f0000017f00000100000000b59f0807000001ffff00000004000012080000016ef1a9ae8d0000016ef1a9aef5110001c0a87a01c0a87aff00000000445c445c000003ffff000000010000009e0000016ef1a9b2a00000016ef1a9b2a0110001ac110001ac11ffff00000000445c445c00ffff0007000000010000009e0000016ef1a9b2a00000016ef1a9b2a0110001ac110001ac11ffff00000000445c445c000007ffff000000010000009e0000016ef1a9b2a00000016ef1a9b2a0110001ac130001ac1300ff00000000445c445c00ffff0006000000010000009e0000016ef1a9b2a00000016ef1a9b2a01100010a000064ffffffff00000000445c445c000002ffff000000010000009e0000016ef1a9b2a00000016ef1a9b2a0110001c0a87a01c0a87aff00000000445c445c00ffff0003000000010000009e0000016ef1a9b2a00000016ef1a9b2a01100010a000064ffffffff00000000445c445c00ffff0002000000010000009e0000016ef1a9b2a00000016ef1a9b2a0110001ac120001ac12ffff00000000445c445c00ffff0005000000010000009e0000016ef1a9b2a00000016ef1a9b2a01100010a0000640a0000ff00000000445c445c000002ffff000000010000009e0000016ef1a9b2a00000016ef1a9b2a0110001ac130001ac1300ff00000000445c445c000006ffff000000010000009e0000016ef1a9b2a00000016ef1a9b2a01100010a0000640a0000ff00000000445c445c00ffff0002000000010000009e0000016ef1a9b2a00000016ef1a9b2a0110001ac120001ac12ffff00000000445c445c000005ffff000000010000009e0000016ef1a9b2a00000016ef1a9b2a0110001000200480104001000080004000c0004000f000400070002000b000200060001000a0002000e00020002000400010004009800080099000800040001000500010088000100d100040104003803d372530a0000640000000001bbda5a180002ffff000000010000006c0000016ef1a9bf250000016ef1a9bf2506000181000000010300344a7d8ebd0a0000640000000001bb9d2c000002ffff00000002000002320000016ef1a9b1000000016ef1a9c8b81100010104006cc1b609730a0000640000000001bbdeb0100002ffff00000001000000340000016ef1a9c9000000016ef1a9c900060001810000000a000064c1b609730a000001deb001bb10ffff000200000001000000340000016ef1a9c8e40000016ef1a9c8e406000181000000010300640a000064010101010a0000018404003500ffff000200000001000000480000016ef1a9cbe00000016ef1a9cbe01100017f0000017f00003500000000ce790035000001ffff000000010000003d0000016ef1a9cbe00000016ef1a9cbe0110001010400380a000064c01eff750a000001e63801bb14ffff000200000001000000340000016ef1a9cbe00000016ef1a9cbe006000381000000010300c47f0000017f00003500000000ce79003500ffff0001000000010000003d0000016ef1a9cbe00000016ef1a9cbe01100017f0000357f000001000000000035ce7900ffff000100000001000000680000016ef1a9cc080000016ef1a9cc081100017f0000357f000001000000000035ce79000001ffff00000001000000680000016ef1a9cc080000016ef1a9cc08110001010101010a0000640000000000358404000002ffff00000001000000730000016ef1a9cc080000016ef1a9cc08110001")

}

func TestIPFixWalk(t *testing.T) {
	var f Filter
	f.SetVersion(10)
	f.SetDomainID(0)

	//test the first couple flows in the packet
	testSet := []cbval{
		cbval{fid: 8, data: []byte{0x7f, 0x00, 0x00, 0x01}},
		cbval{fid: 12, data: []byte{0x7f, 0x00, 0x00, 0x01}},
		cbval{fid: 15, data: []byte{0x00, 0x00, 0x00, 0x00}},
		cbval{fid: 7, data: []byte{0xb5, 0x9f}},
		cbval{fid: 11, data: []byte{0x08, 0x07}},
		cbval{fid: 6, data: []byte{0x00}},
	}

	var cnt int
	cb := func(r *Record, eid uint32, fid uint16, buff []byte) error {
		if eid != 0 {
			return errors.New("invalid enterprise id")
		} else if r.Version != 10 || r.DomainID != 0 {
			return fmt.Errorf("Invalid header: %d %d", r.Version, r.DomainID)
		}
		ft, ok := IPfixIDTypeLookup(eid, fid)
		if !ok {
			return fmt.Errorf("Unknown type %d %d", eid, fid)
		}
		if len(buff) < ft.minLength() {
			return fmt.Errorf("Returned buffer is too small for type: %d < %d", len(buff), ft.minLength())
		}
		if cnt < len(testSet) {
			if eid != testSet[cnt].eid {
				return fmt.Errorf("Flow %d EID bad: %d != %d", cnt, eid, testSet[cnt].eid)
			}
			if fid != testSet[cnt].fid {
				return fmt.Errorf("Flow %d EID bad: %d != %d", cnt, fid, testSet[cnt].fid)
			}
			if !bytes.Equal(buff, testSet[cnt].data) {
				return fmt.Errorf("Bad data: %v != %v", buff, testSet[cnt].data)
			}
		}
		cnt++
		return nil
	}

	w, err := NewWalker(&f, cb, 16, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if err = w.WalkBuffer(walkerPkt); err != nil {
		t.Fatal(err)
	}
	//check the number of call backs against what is in the packet
	if cnt != totalItems {
		t.Fatalf("invalid count: %d != %d", cnt, totalItems)
	}
}

func TestIPFixWalkFilter(t *testing.T) {
	var f Filter
	f.SetVersion(10)
	f.SetDomainID(0)
	// ONLY want SrcAddr and DstAddr
	f.Set(0, 0x8)
	f.Set(0, 12)

	var cnt int
	cb := func(r *Record, eid uint32, fid uint16, buff []byte) error {
		if r.EndOfRecord && buff == nil {
			return nil
		}
		if eid != 0 || !(fid == 0x8 || fid == 12) {
			return errors.New("invalid filtered set")
		} else if r.Version != 10 || r.DomainID != 0 {
			return errors.New("Invalid header")
		} else if len(buff) != 4 {
			//IPv4 address
			return errors.New("Invalid data size")
		}
		cnt++
		return nil
	}
	w, err := NewWalker(&f, cb, 16, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if err = w.WalkBuffer(walkerPkt); err != nil {
		t.Fatal(err)
	}
	if cnt != filteredItems {
		t.Fatalf("Bad item count with filter: %d != %d", cnt, filteredItems)
	}
}

func BenchmarkFullWalk(b *testing.B) {
	var cnt int
	cb := func(r *Record, eid uint32, fid uint16, buff []byte) error {
		if r.EndOfRecord && buff == nil {
			return nil
		}
		if eid != 0 {
			return errors.New("invalid enterprise id")
		}
		cnt++
		return nil
	}
	w, err := NewWalker(nil, cb, 16, 1024)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		cnt = 0
		if err = w.WalkBuffer(walkerPkt); err != nil {
			b.Fatal(err)
		}
		if cnt != totalItems {
			b.Fatalf("Bad item count: %d != %d", cnt, totalItems)
		}
	}
	b.SetBytes(int64(b.N * len(walkerPkt)))
}

func BenchmarkFilterWalk(b *testing.B) {
	var f Filter
	f.SetVersion(10)
	f.Set(0, 8)
	f.Set(0, 12)
	var cnt int
	cb := func(r *Record, eid uint32, fid uint16, buff []byte) error {
		if r.EndOfRecord && buff == nil {
			return nil
		}
		if eid != 0 {
			return errors.New("invalid enterprise id")
		} else if len(buff) != 4 {
			//IPv4 address
			return errors.New("Invalid data size")
		}
		cnt++
		return nil
	}
	w, err := NewWalker(&f, cb, 16, 1024)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		cnt = 0
		if err = w.WalkBuffer(walkerPkt); err != nil {
			b.Fatal(err)
		}
		if cnt != filteredItems {
			b.Fatalf("Bad item count: %d != %d", cnt, filteredItems)
		}
	}
	b.SetBytes(int64(b.N * len(walkerPkt)))
}

func TestNFv9Walk(t *testing.T) {
	//Netflow V9 packet with all required templates included
	pkt, _ := hex.DecodeString("0009001f198afac45defcbd800103e5700000000000000440113000f00080004000c0004000f000400070002000b000200060001000a0002000e000200020004000100040016000400150004000400010005000100d100040113005c34c899db0a0a0a8a0000000001bbbc40180002ffff000000040000013c198a5160198a8aa40600810000000a0a0a8a34c899db0a0a0a01bc4001bb18ffff000200000006000001b0198a5100198a8aa40600810000000000000000400114000e00080004000c0004000f000400070002000b000200060001000a0002000e0002000200040001000400160004001500040004000100050001011400547f0000017f00000100000000d21f115c00ffff00010000000200000b18198a9138198a913811007f0000017f00000100000000d21f115c000001ffff0000000200000b18198a9138198a913811000000011301087f0000017f00000100000000436b898e10ffff00010000000600000138198a5c04198a97000600810000007f0000017f00000100000000898e436b10ffff00010000000600000138198a5c04198a97000600810000007f0000017f00000100000000436b898e100001ffff0000000600000138198a5c04198a97000600810000007f0000017f00000100000000898e436b100001ffff0000000600000138198a5c04198a9700060081000000c6231a600a0a0a8a0000000001bbe904100002ffff0000000200000068198a9830198a98300600810000000a0a0a8ac6231a600a0a0a01e90401bb10ffff00020000000200000068198a9800198a980006008100000000000114002c7f0000017f00000100000000baf9080700ffff000100000002000007dc198aa6c8198aa6c81100000000003c0115000d00080004000c0004000f000400070002000b0002000a0002000e0002000200040001000400160004001500040004000100050001011500507f0000017f00000100000000000003030001ffff0000000400000900198a9138198aa6c801c07f0000017f0000010000000000000303ffff00010000000400000900198a9138198aa6c801c0011402007f0000017f00000100000000baf90807000001ffff00000002000007dc198aa6c8198aa6c811000a0a0a010a0a0a8a000000000035928c000002ffff0000000200000154198abb20198abb2011000a0a0a8a0a0a0a0100000000dbd8003500ffff0002000000020000008e198abb1c198abb1c11000a0a0a8a0a0a0a0100000000928c003500ffff0002000000020000008e198abb1c198abb1c11000a0a0a010a0a0a8a000000000035dbd8000002ffff0000000200000132198abb20198abb2011000a0a0a8a0a0a0a0100000000cae8003500ffff0002000000020000008e198abb88198abb8811000a0a0a8a0a0a0a0100000000c167003500ffff0002000000020000008e198abb88198abb8811000a0a0a010a0a0a8a000000000035cae8000002ffff0000000200000154198abb8c198abb8c11000a0a0a010a0a0a8a000000000035c167000002ffff0000000200000132198abb8c198abb8c11000a0a0a010a0a0a8a0000000000359012000002ffff0000000200000132198abd90198abd9011000a0a0a010a0a0a8a0000000000358df4000002ffff0000000200000154198abd90198abd9011000a0a0a8a0a0a0a01000000008df4003500ffff0002000000020000008e198abd8c198abd8c11000a0a0a8a0a0a0a01000000009012003500ffff0002000000020000008e198abd8c198abd8c1100000113005a0a0a0a8a976500850a0a0a01e74201bb10ffff00020000000200000068198ac000198ac000060081000000976500850a0a0a8a0000000001bbe742100002ffff0000000200000068198ac020198ac020060081000000")

	var f Filter
	f.SetVersion(9)

	//test the first couple flows in the packet
	testSet := []cbval{
		cbval{fid: 8, data: []byte{52, 200, 153, 219}},       // srcaddr = 52.200.153.219
		cbval{fid: 12, data: []byte{10, 10, 10, 138}},        // dstaddr = 10.10.10.138
		cbval{fid: 15, data: []byte{0x00, 0x00, 0x00, 0x00}}, // nexthop = 0.0.0.0
		cbval{fid: 7, data: []byte{0x1, 0xbb}},               // srcport = 443
		cbval{fid: 11, data: []byte{0xbc, 0x40}},             // dstport = 48192
		cbval{fid: 6, data: []byte{0x18}},                    // tcp flags = 0x18 (ACK, PSH)
	}

	var cnt int
	cb := func(r *Record, eid uint32, fid uint16, buff []byte) error {
		if r.EndOfRecord && buff == nil {
			return nil
		}
		if eid != 0 {
			return errors.New("invalid enterprise id")
		}
		if cnt < len(testSet) {
			if eid != testSet[cnt].eid {
				return fmt.Errorf("Flow %d EID bad: %d != %d", cnt, eid, testSet[cnt].eid)
			}
			if fid != testSet[cnt].fid {
				return fmt.Errorf("Flow %d EID bad: %d != %d", cnt, fid, testSet[cnt].fid)
			}
			if !bytes.Equal(buff, testSet[cnt].data) {
				return fmt.Errorf("Bad data for idx %v: %v != %v", cnt, buff, testSet[cnt].data)
			}
		}
		cnt++
		return nil
	}

	w, err := NewWalker(&f, cb, 16, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if err = w.WalkBuffer(pkt); err != nil {
		t.Fatal(err)
	}
	//check the number of call backs against what is in the packet
	totalItems := (15*10 + 14*16 + 13*2)
	if cnt != totalItems {
		t.Fatalf("invalid count: %d != %d", cnt, totalItems)
	}
}
