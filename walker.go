package ipfix

import (
	"errors"
	"io"
)

var (
	ErrNilCallback = errors.New("nil callback")
)

type RecordCallback func(*Record, uint32, uint16, []byte) error

type Record struct {
	MessageHeader
	SetID        int
	DataRecordID int
	EndOfRecord  bool
	Err          error
}

type Walker struct {
	cb         RecordCallback
	f          *Filter
	filtering  bool
	headerOnly bool
	trbuf      []TemplateRecord
	fidbuf     []TemplateFieldSpecifier
}

// NewWalker creates a new Walker object. It will use the given Filter
// to perform pre-filtering of entries. trbufsize and fidbufsize give
// sizes to use when pre-allocating the template record buffer
// and the template field specifier buffer, respectively; 64 and 4096
// would be safe defaults to use.
func NewWalker(f *Filter, trbufsize, fidbufsize int) (w *Walker, err error) {
	if trbufsize <= 0 {
		trbufsize = 32
	}
	if fidbufsize <= 0 {
		fidbufsize = 1024
	}
	w = &Walker{
		f:         f,
		filtering: f != nil,
		trbuf:     make([]TemplateRecord, 0, trbufsize),          //eeeh, sure
		fidbuf:    make([]TemplateFieldSpecifier, 0, fidbufsize), //eeeh, sure
	}
	return
}

// SetHeaderOnly can be used to enable header-only parsing via the
// walker. If set to true, the WalkBuffer function will call the
// callback only once, with an EID and FID of 0.
func (w *Walker) SetHeaderOnly(v bool) {
	w.headerOnly = v
}

// WalkBuffer walks an IPFIX or Netflow V9 packet in buf, calling
// the callback function in accordance with the following rules:
//
// 1. If SetHeaderOnly(true) was called, the callback will be called
// precisely once, with EndOfRecord set in the record parameter,
// EID and FID set to zero, and a nil buffer. This allows code
// to view the packet header only.
//
// 2. If a nil Filter was passed when building the Walker, the callback
// will be called for every field in each record. When a record has
// been fully processed, the callback will be called again with
// EndOfRecord set to true, EID and FID set to zero, and a nil buffer.
// The next record will then be processed, and so on until the message
// has been fully read.
//
// 3. If a non-nil Filter was passed, the function will behave exactly
// as in case #2 except that only those EID and FID combinations registered
// with the Filter will trigger a callback. The EndOfRecord callback
// will still occur as normal.
func (w *Walker) WalkBuffer(buf []byte, cb RecordCallback) (err error) {
	var r Record
	if cb == nil {
		err = ErrNilCallback
		return
	}
	w.cb = cb

	sl := slice{bs: buf}
	r.MessageHeader.unmarshal(&sl)
	if w.filtering && w.f.FilterHeader(r.DomainID, r.Version) {
		return
	}
	if w.headerOnly {
		// only processing the header
		r.EndOfRecord = true
		err = w.cb(&r, 0, 0, nil)
	} else {
		switch r.Version {
		case ipfixVersion:
			err = w.walkIpfixBuffer(&sl, &r)
		case nfv9Version:
			err = w.walkNfv9Buffer(&sl, &r)
		default:
			err = ErrVersion
		}
	}
	return
}

func (w *Walker) walkIpfixBuffer(sl *slice, r *Record) (err error) {
	var sh setHeader
	var nsl slice
	//reset the template record buffer
	w.trbuf = w.trbuf[0:0]
	//reset our template filds buffer
	w.fidbuf = w.fidbuf[0:0]

	for {
		l := sl.Len()
		if l == 0 {
			break
		} else if l < setHeaderLength {
			err = io.ErrUnexpectedEOF
			break
		}
		sh.unmarshal(sl)

		if sh.Length < setHeaderLength {
			err = io.ErrUnexpectedEOF
			break
		}
		// Grab the bytes representing the set
		setLen := int(sh.Length) - setHeaderLength
		nsl.bs = sl.Cut(setLen)
		if err = sl.Error(); err != nil {
			break
		}
		if err = w.walkIPFixSet(r, &sh, &nsl); err != nil {
			break
		}
		r.SetID++
	}

	return
}

func (w *Walker) walkIPFixSet(r *Record, sh *setHeader, sl *slice) (err error) {
	var tmpl TemplateRecord
	var ok bool
	r.DataRecordID = 0
	var minLen uint16

	for sl.Len() > 0 && sl.Error() == nil {
		if sl.Len() < int(minLen) {
			if debug {
				dl.Println("ignoring padding")
			}
			// Padding
			return
		}
		switch {
		case sh.SetID < 2:
			// Unused, shouldn't happen
			//make the callback with a parse error
			err = ErrProtocol
			return
		case sh.SetID == 2:
			if err = w.readTemplateRecord(sl); err != nil {
				return
			}
		case sh.SetID == 3:
			// Options Template Set, not handled
			sl.Cut(sl.Len())
		case sh.SetID > 3 && sh.SetID < 256:
			// Reserved, shouldn't happen
			err = ErrProtocol
			return
		default:
			// actual data record
			if tmpl, ok = w.lookupTemplateRecord(sh.SetID); !ok {
				//run the callback with the unknown template
				err = ErrUnknownTemplate
				return
			}
			if minLen == 0 {
				minLen = calcMinRecLen(tmpl.FieldSpecifiers)
			}
			if err = w.handleDataRecord(r, sh, tmpl.FieldSpecifiers, sl); err != nil {
				return
			}
		}
		r.DataRecordID++
	}
	return
}

func (w *Walker) handleDataRecord(r *Record, sh *setHeader, tpl []TemplateFieldSpecifier, sl *slice) (err error) {
	var val []byte
	var l int
	var lo uint8
	var hit bool

	//reset the record items
	r.Err = nil
	r.EndOfRecord = false

	for i := range tpl {
		if l = int(tpl[i].Length); l == 0xffff {
			if len(sl.bs) == 0 {
				return ErrRead
			}
			if lo = sl.bs[0]; lo < 0xff {
				l = int(lo)
				sl.bs = sl.bs[1:]
			} else {
				if len(sl.bs) < 2 {
					return ErrRead
				}
				l = int((uint16(sl.bs[0]) << 8) + uint16(sl.bs[1]))
				sl.bs = sl.bs[2:]
			}
		}
		if l > len(sl.bs) {
			return ErrRead
		}
		val = sl.bs[:l]
		sl.bs = sl.bs[l:]
		/* old code using this cut nonsense
		val = sl.Cut(l)
		if err = sl.Error(); err != nil {
			return err
		}
		*/
		if w.filtering && !w.f.IsSet(tpl[i].EnterpriseID, tpl[i].FieldID) {
			continue //not looking at this item
		}
		hit = true
		if err = w.cb(r, tpl[i].EnterpriseID, tpl[i].FieldID, val); err != nil {
			return
		}
	}
	err = sl.Error()
	if hit {
		r.Err = err
		r.EndOfRecord = true
		w.cb(r, 0, 0, nil)
	}
	return
}

func (w *Walker) readTemplateRecord(sl *slice) (err error) {
	var tr TemplateRecord
	var th templateHeader
	th.unmarshal(sl)
	if err = sl.Error(); err != nil {
		return
	}
	tr.TemplateID = th.TemplateID
	specs := w.allocateTemplateFieldSpecifiers(th.FieldCount)
	for i := uint16(0); i < th.FieldCount; i++ {
		specs[i].EnterpriseID = uint32(0)
		specs[i].FieldID = sl.Uint16()
		specs[i].Length = sl.Uint16()
		if specs[i].FieldID >= 0x8000 {
			specs[i].FieldID -= 0x8000
			specs[i].EnterpriseID = sl.Uint32()
		}
		if err = sl.Error(); err != nil {
			return
		}
	}
	tr.FieldSpecifiers = specs
	w.trbuf = append(w.trbuf, tr)
	return
}

func (w *Walker) lookupTemplateRecord(sid uint16) (tmp TemplateRecord, ok bool) {
	for i := range w.trbuf {
		if w.trbuf[i].TemplateID == sid {
			tmp = w.trbuf[i]
			ok = true
			break
		}
	}
	return
}

func (w *Walker) allocateTemplateFieldSpecifiers(cnt uint16) (r []TemplateFieldSpecifier) {
	c := cap(w.fidbuf)
	l := len(w.fidbuf)
	if int(cnt) < (c - l) {
		e := l + int(cnt) //mark the new end
		r = w.fidbuf[l:e]
		w.fidbuf = w.fidbuf[0:e] //set the new length
	} else {
		//we ran out of space, allocate :(
		r = make([]TemplateFieldSpecifier, cnt)
	}
	return
}

func (w *Walker) walkNfv9Buffer(sl *slice, r *Record) (err error) {
	var sh setHeader
	var nsl slice
	//reset the template record buffer
	w.trbuf = w.trbuf[0:0]
	//reset our template filds buffer
	w.fidbuf = w.fidbuf[0:0]

	for {
		l := sl.Len()
		if l == 0 {
			break
		} else if l < setHeaderLength {
			err = io.ErrUnexpectedEOF
			break
		}
		sh.unmarshal(sl)
		if sh.Length < setHeaderLength {
			err = io.ErrUnexpectedEOF
			break
		}
		// Grab the bytes representing the set
		setLen := int(sh.Length) - setHeaderLength
		nsl.bs = sl.Cut(setLen)
		if err = sl.Error(); err != nil {
			break
		}
		if err = w.walkNFv9Set(r, &sh, &nsl); err != nil {
			break
		}
	}

	return

}

func (w *Walker) walkNFv9Set(r *Record, sh *setHeader, sl *slice) (err error) {
	var tmpl TemplateRecord
	var ok bool
	r.DataRecordID = 0
	var minLen uint16

	for sl.Len() > 0 && sl.Error() == nil {
		if sl.Len() < int(minLen) {
			if debug {
				dl.Println("ignoring padding")
			}
			// Padding
			return
		}
		switch {
		case sh.SetID == 0:
			if err = w.readTemplateRecord(sl); err != nil {
				return
			}
		case sh.SetID == 1:
			// Options Template Set, not handled
			sl.Cut(sl.Len())
		case sh.SetID > 2 && sh.SetID < 256:
			// Reserved, shouldn't happen
			err = ErrProtocol
			return
		default:
			// actual data record
			if tmpl, ok = w.lookupTemplateRecord(sh.SetID); !ok {
				//run the callback with the unknown template
				err = ErrUnknownTemplate
				return
			}
			if minLen == 0 {
				minLen = calcMinRecLen(tmpl.FieldSpecifiers)
			}
			if err = w.handleDataRecord(r, sh, tmpl.FieldSpecifiers, sl); err != nil {
				return
			}
		}
	}
	return

}
