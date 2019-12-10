package ipfix

import (
//"errors"
)

type HeaderFilter struct {
	Version       uint16 //v9 or v10
	versionActive bool
	DomainID      uint32
	domainActive  bool
}

type otherFilter struct {
	uint16Bitmask
	eid uint32
}

type Filter struct {
	HeaderFilter
	uint16Bitmask
	baseEnabled bool
	others      []otherFilter
}

func (f *Filter) SetVersion(v uint16) {
	f.versionActive = true
	f.Version = v
}

func (f *Filter) ClearVersion() {
	f.versionActive = false
}

func (f *Filter) SetDomainID(v uint32) {
	f.domainActive = true
	f.DomainID = v
}

func (f *Filter) ClearDomainID() {
	f.domainActive = false
}

func (f *Filter) FilterHeader(did uint32, ver uint16) bool {
	if f.domainActive && f.DomainID != did {
		return true
	} else if f.versionActive && f.Version != ver {
		return true
	}
	return false
}

func (f *Filter) Set(eid uint32, id uint16) {
	if eid == 0 {
		f.set(id)
		f.baseEnabled = true
		return
	} else {
		for i := range f.others {
			if f.others[i].eid == eid {
				f.others[i].set(id)
				return
			}
		}
	}
	//if we hit here, we need to add another bitmap filter
	nf := otherFilter{eid: eid}
	nf.set(id)
	f.others = append(f.others, nf)
}

func (f *Filter) IsSet(eid uint32, id uint16) bool {
	if eid == 0 {
		if !f.baseEnabled {
			return true
		}
		return f.isset(id)
	} else {
		for i := range f.others {
			if f.others[i].eid == eid {
				return f.others[i].isset(id)
			}
		}
	}
	//filter not set for this eid
	return true
}

func (f *Filter) Clear(eid uint32, id uint16) {
	if eid == 0 {
		f.clear(id)
		return
	} else {
		for i := range f.others {
			if f.others[i].eid == eid {
				f.others[i].clear(id)
				return
			}
		}
	}
}

type uint16Bitmask struct {
	bits [0x2000]byte
}

func (u *uint16Bitmask) set(v uint16) {
	mask := byte(1 << byte(v&0x7))
	off := v >> 3
	u.bits[off] |= mask
}

func (u *uint16Bitmask) clear(v uint16) {
	mask := byte(1 << byte(v&0x7))
	off := v >> 3
	u.bits[off] &= (mask ^ 0xff)
}

func (u *uint16Bitmask) isset(v uint16) bool {
	mask := byte(1 << byte(v&0x7))
	off := v >> 3
	return (u.bits[off] & mask) != 0
}
