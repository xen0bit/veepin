// Package softether implements the wire format of the SoftEther VPN native
// protocol (SE-VPN): Ethernet frames over TLS with a self-describing key/value
// serialisation called "PACK" for control messages, and raw Ethernet frames for
// data.
//
// PACK format (SoftEtherVPN/src/Mayaqua/Pack.c):
//   - Little-endian integers throughout.
//   - Header: element-count uint32, then that many ELEMENTs.
//   - ELEMENT:
//     name:   NUL-terminated ASCII (max 63 chars + NUL).
//     type:   uint32 (0=INT, 1=DATA, 2=STR, 3=UNISTR, 4=INT64).
//     count:  uint32 (number of values).
//     values: count × VALUE, each depending on type.
//   - VALUE types:
//     INT:    uint32 (4 bytes).
//     INT64:  uint64 (8 bytes).
//     DATA:   length uint32, then length bytes of raw data.
//     STR:    length uint32, then length bytes of ASCII.
//     UNISTR: length uint32, then length bytes of UTF-8.
//
// Data frames are raw Ethernet frames (no PACK wrapping), read from / written
// to a TAP device.
package softether

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Element value type constants, matching SoftEther's VALUE_* defines.
const (
	TypeInt    = 0
	TypeData   = 1
	TypeStr    = 2
	TypeUniStr = 3
	TypeInt64  = 4
)

// Limits matching SoftEther's MAX_* defines (64-bit platform values).
const (
	MaxElementNameLen = 63
	MaxValueSize      = 384 * 1024 * 1024 // per VALUE
	MaxValueNum       = 262144            // per ELEMENT
	MaxElementNum     = 262144            // per PACK
	MaxPackSize       = 512 * 1024 * 1024
)

var (
	ErrTruncated       = errors.New("softether: truncated PACK data")
	ErrTooManyElements = errors.New("softether: too many elements")
	ErrTooManyValues   = errors.New("softether: too many values")
	ErrValueTooLarge   = errors.New("softether: value too large")
	ErrUnknownType     = errors.New("softether: unknown element type")
	ErrNameTooLong     = errors.New("softether: element name too long")
)

// Pack is a self-describing key/value container used for SoftEther control
// messages. It maps names to elements, where each element has a type and one
// or more values (arrays).
type Pack struct {
	elems []Element
}

// Element is a named collection of typed values.
type Element struct {
	Name   string
	Type   int
	Values []Value
}

// Value holds a single value of one of the five PACK types.
type Value struct {
	Int    uint32
	Int64  uint64
	Data   []byte
	Str    string
	UniStr string // stored as Go string (UTF-8 on wire)
}

// NewPack returns an empty Pack.
func NewPack() *Pack { return &Pack{} }

// Add appends a single-valued element.
func (p *Pack) Add(name string, typ int, v Value) {
	p.elems = append(p.elems, Element{Name: name, Type: typ, Values: []Value{v}})
}

// AddMulti appends a multi-valued element.
func (p *Pack) AddMulti(name string, typ int, vals []Value) {
	p.elems = append(p.elems, Element{Name: name, Type: typ, Values: vals})
}

// Get returns the first element with the given name, or nil.
func (p *Pack) Get(name string) *Element {
	for i := range p.elems {
		if p.elems[i].Name == name {
			return &p.elems[i]
		}
	}
	return nil
}

// GetInt returns the int value of a named element, or 0.
func (p *Pack) GetInt(name string) uint32 {
	if e := p.Get(name); e != nil && e.Type == TypeInt && len(e.Values) > 0 {
		return e.Values[0].Int
	}
	return 0
}

// GetStr returns the string value of a named element, or "".
func (p *Pack) GetStr(name string) string {
	if e := p.Get(name); e != nil && e.Type == TypeStr && len(e.Values) > 0 {
		return e.Values[0].Str
	}
	return ""
}

// GetData returns the data value of a named element, or nil.
func (p *Pack) GetData(name string) []byte {
	if e := p.Get(name); e != nil && e.Type == TypeData && len(e.Values) > 0 {
		return e.Values[0].Data
	}
	return nil
}

// Encode serialises the Pack into bytes.
func (p *Pack) Encode() ([]byte, error) {
	if len(p.elems) > MaxElementNum {
		return nil, ErrTooManyElements
	}
	// Upper bound: 4 (count) + sum of element sizes.
	// Each element: name (up to 65), type(4), count(4) + values.
	size := 4
	for _, e := range p.elems {
		size += len(e.Name) + 1 + 4 + 4 // name+NUL + type + count
		for _, v := range e.Values {
			size += valueWireSize(e.Type, v)
		}
	}
	if size > MaxPackSize {
		return nil, ErrValueTooLarge
	}
	b := make([]byte, 0, size)
	b = binary.LittleEndian.AppendUint32(b, uint32(len(p.elems)))
	for _, e := range p.elems {
		if len(e.Name) > MaxElementNameLen {
			return nil, ErrNameTooLong
		}
		b = append(b, e.Name...)
		b = append(b, 0) // NUL terminator
		b = binary.LittleEndian.AppendUint32(b, uint32(e.Type))
		b = binary.LittleEndian.AppendUint32(b, uint32(len(e.Values)))
		for _, v := range e.Values {
			var err error
			b, err = appendValue(b, e.Type, v)
			if err != nil {
				return nil, err
			}
		}
	}
	return b, nil
}

// Decode parses a Pack from bytes. It returns subslices of the input — no
// allocation per element for the data/str bodies (strings are still allocated
// by Go's type system).
func Decode(buf []byte) (*Pack, error) {
	orig := buf
	if len(buf) < 4 {
		return nil, ErrTruncated
	}
	count := binary.LittleEndian.Uint32(buf)
	buf = buf[4:]
	if count > MaxElementNum {
		return nil, ErrTooManyElements
	}
	p := &Pack{elems: make([]Element, 0, count)}
	for range count {
		e, err := decodeElement(&buf)
		if err != nil {
			return nil, err
		}
		p.elems = append(p.elems, e)
	}
	_ = orig // keep reference to the backing array
	return p, nil
}

func decodeElement(buf *[]byte) (Element, error) {
	// Name: NUL-terminated ASCII.
	name, err := readCString(buf)
	if err != nil {
		return Element{}, err
	}
	if len(*buf) < 8 {
		return Element{}, ErrTruncated
	}
	typ := binary.LittleEndian.Uint32((*buf)[:4])
	*buf = (*buf)[4:]
	nv := binary.LittleEndian.Uint32((*buf)[:4])
	*buf = (*buf)[4:]

	if nv > MaxValueNum {
		return Element{}, ErrTooManyValues
	}
	e := Element{Name: name, Type: int(typ)}
	e.Values = make([]Value, nv)
	for i := range nv {
		v, err := decodeValue(buf, int(typ))
		if err != nil {
			return Element{}, err
		}
		e.Values[i] = v
	}
	return e, nil
}

func decodeValue(buf *[]byte, typ int) (Value, error) {
	switch typ {
	case TypeInt:
		if len(*buf) < 4 {
			return Value{}, ErrTruncated
		}
		v := binary.LittleEndian.Uint32((*buf)[:4])
		*buf = (*buf)[4:]
		return Value{Int: v}, nil

	case TypeInt64:
		if len(*buf) < 8 {
			return Value{}, ErrTruncated
		}
		v := binary.LittleEndian.Uint64((*buf)[:8])
		*buf = (*buf)[8:]
		return Value{Int64: v}, nil

	case TypeData:
		if len(*buf) < 4 {
			return Value{}, ErrTruncated
		}
		sz := binary.LittleEndian.Uint32((*buf)[:4])
		*buf = (*buf)[4:]
		if sz > MaxValueSize {
			return Value{}, ErrValueTooLarge
		}
		if uint32(len(*buf)) < sz {
			return Value{}, ErrTruncated
		}
		// Return subslice of the input — no copy.
		v := (*buf)[:sz]
		*buf = (*buf)[sz:]
		return Value{Data: v}, nil

	case TypeStr:
		if len(*buf) < 4 {
			return Value{}, ErrTruncated
		}
		sz := binary.LittleEndian.Uint32((*buf)[:4])
		*buf = (*buf)[4:]
		if sz > MaxValueSize {
			return Value{}, ErrValueTooLarge
		}
		if uint32(len(*buf)) < sz {
			return Value{}, ErrTruncated
		}
		s := string((*buf)[:sz])
		*buf = (*buf)[sz:]
		return Value{Str: s}, nil

	case TypeUniStr:
		if len(*buf) < 4 {
			return Value{}, ErrTruncated
		}
		sz := binary.LittleEndian.Uint32((*buf)[:4])
		*buf = (*buf)[4:]
		if sz > MaxValueSize {
			return Value{}, ErrValueTooLarge
		}
		if uint32(len(*buf)) < sz {
			return Value{}, ErrTruncated
		}
		s := string((*buf)[:sz])
		*buf = (*buf)[sz:]
		return Value{UniStr: s}, nil

	default:
		return Value{}, fmt.Errorf("%w: %d", ErrUnknownType, typ)
	}
}

func valueWireSize(typ int, v Value) int {
	switch typ {
	case TypeInt:
		return 4
	case TypeInt64:
		return 8
	case TypeData:
		return 4 + len(v.Data)
	case TypeStr:
		return 4 + len(v.Str)
	case TypeUniStr:
		return 4 + len(v.UniStr)
	default:
		return 0
	}
}

func appendValue(b []byte, typ int, v Value) ([]byte, error) {
	switch typ {
	case TypeInt:
		return binary.LittleEndian.AppendUint32(b, v.Int), nil
	case TypeInt64:
		return binary.LittleEndian.AppendUint64(b, v.Int64), nil
	case TypeData:
		if uint32(len(v.Data)) > MaxValueSize {
			return nil, ErrValueTooLarge
		}
		b = binary.LittleEndian.AppendUint32(b, uint32(len(v.Data)))
		return append(b, v.Data...), nil
	case TypeStr:
		if len(v.Str) > MaxValueSize {
			return nil, ErrValueTooLarge
		}
		b = binary.LittleEndian.AppendUint32(b, uint32(len(v.Str)))
		return append(b, v.Str...), nil
	case TypeUniStr:
		// Unicode strings are stored as UTF-8 on wire.
		utf8 := v.UniStr
		if uint32(len(utf8)) > MaxValueSize {
			return nil, ErrValueTooLarge
		}
		b = binary.LittleEndian.AppendUint32(b, uint32(len(utf8)))
		return append(b, utf8...), nil
	default:
		return nil, fmt.Errorf("%w: %d", ErrUnknownType, typ)
	}
}

func readCString(buf *[]byte) (string, error) {
	for i := range *buf {
		if (*buf)[i] == 0 {
			s := string((*buf)[:i])
			*buf = (*buf)[i+1:]
			if len(s) > MaxElementNameLen {
				return "", ErrNameTooLong
			}
			return s, nil
		}
	}
	return "", ErrTruncated
}

// IntValue returns a Value containing a uint32.
func IntValue(v uint32) Value { return Value{Int: v} }

// Int64Value returns a Value containing a uint64.
func Int64Value(v uint64) Value { return Value{Int64: v} }

// DataValue returns a Value containing a byte slice.
func DataValue(v []byte) Value { return Value{Data: v} }

// StrValue returns a Value containing a string.
func StrValue(v string) Value { return Value{Str: v} }

// UniStrValue returns a Value containing a Unicode string (UTF-8).
func UniStrValue(v string) Value { return Value{UniStr: v} }
