package ipfix

import (
	"errors"
	"io"
)

type RecordCallback func(*Record, uint32, uint16, []byte) error

type Record struct {
	MessageHeader
	SetID        int
	DataRecordID int
}

type Walker struct {
	cb        RecordCallback
	f         *Filter
	filtering bool
	trbuf     []TemplateRecord
	fidbuf    []TemplateFieldSpecifier
}

func NewWalker(f *Filter, cb RecordCallback, trbufsize, fidbufsize int) (w *Walker, err error) {
	if cb == nil {
		err = errors.New("nil callback")
		return
	}
	if trbufsize <= 0 {
		trbufsize = 32
	}
	if fidbufsize <= 0 {
		fidbufsize = 1024
	}
	w = &Walker{
		cb:        cb,
		f:         f,
		filtering: f != nil,
		trbuf:     make([]TemplateRecord, 0, trbufsize),          //eeeh, sure
		fidbuf:    make([]TemplateFieldSpecifier, 0, fidbufsize), //eeeh, sure
	}
	return
}

func (w *Walker) WalkBuffer(buf []byte) (err error) {
	var r Record
	sl := slice{bs: buf}
	r.MessageHeader.unmarshal(&sl)
	if w.filtering && w.f.FilterHeader(r.DomainID, r.Version) {
		return
	}
	switch r.Version {
	case ipfixVersion:
		err = w.walkIpfixBuffer(&sl, &r)
	case nfv9Version:
		err = w.walkNfv9Buffer(&sl, &r)
	default:
		err = ErrVersion
	}
	return
}

func (w *Walker) walkIpfixBuffer(sl *slice, r *Record) (err error) {
	var sh setHeader
	var nsl slice
	//reset the template record buffer
	w.trbuf = w.trbuf[:]
	//reset our template filds buffer
	w.fidbuf = w.fidbuf[:]

	for {
		l := sl.Len()
		if l == 0 {
			break
		} else if l < setHeaderLength {
			err = io.ErrUnexpectedEOF
			break
		}
		sh.unmarshal(sl)
		if r.MessageHeader.Length < setHeaderLength {
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

	for sl.Len() > 0 && sl.Error() == nil {
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
			} else if err = w.handleDataRecord(r, sh, tmpl.FieldSpecifiers, sl); err != nil {
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
	for i := range tpl {
		if tpl[i].Length == 0xffff {
			if lo = sl.Uint8(); lo < 0xff {
				l = int(lo)
			} else {
				l = int(sl.Uint16())
			}
		} else {
			l = int(tpl[i].Length)
		}
		val = sl.Cut(l)
		if err = sl.Error(); err != nil {
			return err
		}
		if w.filtering && !w.f.IsSet(tpl[i].EnterpriseID, tpl[i].FieldID) {
			continue //not looking at this item
		}

		if err = w.cb(r, tpl[i].EnterpriseID, tpl[i].FieldID, val); err != nil {
			return
		}
	}
	err = sl.Error()
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
	//reset the template record buffer
	w.trbuf = w.trbuf[:]
	//reset our template filds buffer
	w.fidbuf = w.fidbuf[:]

	err = errors.New("not ready")
	return
}

func (w *Walker) walkNFv9Set(sh *setHeader, setSl *slice) (err error) {
	err = errors.New("not ready")
	return
}
