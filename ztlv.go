// Package ztlv implements a security-focused, low-allocation Tag-Length-Value (TLV)
// binary encoder and decoder operating directly on io.Writer and io.Reader streams.
//
// Wire format for each TLV record:
//   - Tag:    1 byte  (uint8, 0x00-0xFF)
//   - Length: 4 bytes (uint32, Big Endian, payload size in bytes)
//   - Value:  N bytes (raw payload)
package ztlv

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"time"
	"unsafe"
)

var (
	// ErrPayloadTooLarge is returned when a payload or skip size exceeds configured limits or uint32 bounds.
	ErrPayloadTooLarge = errors.New("ztlv: payload exceeds configured limit")
	// ErrListTooLarge is returned when a string list count exceeds MaxListCount.
	ErrListTooLarge = errors.New("ztlv: list count exceeds configured limit")
	// ErrShortBuffer is returned when a caller-provided destination slice is smaller than the payload.
	ErrShortBuffer = errors.New("ztlv: buffer too short")
	// ErrInvalidTag is returned (or wrapped by UnexpectedTagError) when an unexpected tag is encountered.
	ErrInvalidTag = errors.New("ztlv: invalid tag found")
	// ErrInvalidLength is returned when a length prefix does not match the expected type size or framing.
	ErrInvalidLength = errors.New("ztlv: invalid length for type")
	// ErrInvalidTime is returned when a decoded timestamp has out-of-range nanoseconds (>= 1e9).
	ErrInvalidTime = errors.New("ztlv: invalid timestamp")
)

const (
	// DefaultMaxStringSize is the default maximum byte length allowed by ReadString (1 MiB).
	DefaultMaxStringSize = 1 << 20
	// DefaultMaxBytesSize is the default maximum byte length allowed by ReadBytes and ReadBytesInto (10 MiB).
	DefaultMaxBytesSize = 10 << 20
	// DefaultMaxListCount is the default maximum number of strings allowed by ReadStrings (1000).
	DefaultMaxListCount = 1000
	// DefaultMaxSkipSize is the default maximum byte count allowed by Skip and nested trailing drain (10 MiB).
	DefaultMaxSkipSize = 10 << 20

	maxNestedBufRetain = 64 << 10 // Drop oversized nested encode buffers above 64 KiB after flush.
	maxListPrealloc    = 256      // Cap initial slice preallocation to prevent OOM on truncated streams.
)

// Tag is a single-byte TLV identifier (0x00-0xFF).
type Tag byte

// UnexpectedTagError is returned when the read tag does not match the expected tag.
type UnexpectedTagError struct {
	Expected Tag
	Actual   Tag
}

// Error implements the error interface.
func (e *UnexpectedTagError) Error() string {
	return fmt.Sprintf("ztlv: expected tag 0x%02X, got 0x%02X", e.Expected, e.Actual)
}

// Unwrap allows matching with errors.Is(err, ErrInvalidTag).
func (e *UnexpectedTagError) Unwrap() error { return ErrInvalidTag }

// ShortBufferError is returned when a caller-provided slice cannot hold the decoded payload.
// Callers may unwrap ErrShortBuffer or inspect Required to resize and retry ReadBytesInto.
type ShortBufferError struct {
	Required  uint32
	Available int
}

// Error implements the error interface.
func (e *ShortBufferError) Error() string {
	return fmt.Sprintf("%s: need %d bytes, got %d", ErrShortBuffer, e.Required, e.Available)
}

// Unwrap allows matching with errors.Is(err, ErrShortBuffer).
func (e *ShortBufferError) Unwrap() error { return ErrShortBuffer }

// --- ENCODER ---

// Encoder writes TLV-encoded values to an io.Writer using a stack-embedded scratch buffer.
// An Encoder is not safe for concurrent use by multiple goroutines.
type Encoder struct {
	w         io.Writer
	scratch   [17]byte // Fits max fixed TLV: 1 (Tag) + 4 (Length) + 12 (Time).
	nestedBuf *bytes.Buffer
	nestedEnc *Encoder
}

// NewEncoder returns a new Encoder writing to w (which must be non-nil).
func NewEncoder(w io.Writer) *Encoder {
	return &Encoder{w: w}
}

// Reset reuses the Encoder with a new io.Writer without reallocating internal state.
func (e *Encoder) Reset(w io.Writer) {
	e.w = w
	if e.nestedBuf != nil {
		e.nestedBuf.Reset()
	}
}

func (e *Encoder) putTLVHeader(tag Tag, length uint32) {
	e.scratch[0] = byte(tag)
	binary.BigEndian.PutUint32(e.scratch[1:5], length)
}

func boolByte(v bool) byte {
	if v {
		return 0x01
	}
	return 0x00
}

func putTime(dst []byte, t time.Time) {
	// Store 64-bit Unix seconds + 32-bit nanoseconds to avoid Y2038 and Y2262 overflows.
	// #nosec G115 -- two's-complement bit pattern preserves pre-1970 negative Unix seconds.
	binary.BigEndian.PutUint64(dst[:8], uint64(t.Unix()))
	// #nosec G115 -- time.Time.Nanosecond() is always in [0, 999999999].
	binary.BigEndian.PutUint32(dst[8:12], uint32(t.Nanosecond()))
}

// WriteTag writes a single-byte Tag without length or value.
func (e *Encoder) WriteTag(tag Tag) error {
	e.scratch[0] = byte(tag)
	_, err := e.w.Write(e.scratch[:1])
	return err
}

// WriteLength writes a 4-byte Big Endian uint32 length prefix.
func (e *Encoder) WriteLength(length uint32) error {
	binary.BigEndian.PutUint32(e.scratch[:4], length)
	_, err := e.w.Write(e.scratch[:4])
	return err
}

// WriteTime encodes a timestamp as 12 raw bytes (int64 seconds + uint32 nanoseconds) without a length prefix.
func (e *Encoder) WriteTime(t time.Time) error {
	putTime(e.scratch[:12], t)
	_, err := e.w.Write(e.scratch[:12])
	return err
}

// WriteBool writes a raw boolean byte (0x01 for true, 0x00 for false).
func (e *Encoder) WriteBool(v bool) error {
	e.scratch[0] = boolByte(v)
	_, err := e.w.Write(e.scratch[:1])
	return err
}

// WriteUint8 writes a raw uint8 (1 byte).
func (e *Encoder) WriteUint8(v uint8) error {
	e.scratch[0] = v
	_, err := e.w.Write(e.scratch[:1])
	return err
}

// WriteUint16 writes a raw uint16 (2 bytes, Big Endian).
func (e *Encoder) WriteUint16(v uint16) error {
	binary.BigEndian.PutUint16(e.scratch[:2], v)
	_, err := e.w.Write(e.scratch[:2])
	return err
}

// WriteUint32 writes a raw uint32 (4 bytes, Big Endian).
func (e *Encoder) WriteUint32(v uint32) error {
	binary.BigEndian.PutUint32(e.scratch[:4], v)
	_, err := e.w.Write(e.scratch[:4])
	return err
}

// WriteUint64 writes a raw uint64 (8 bytes, Big Endian).
func (e *Encoder) WriteUint64(v uint64) error {
	binary.BigEndian.PutUint64(e.scratch[:8], v)
	_, err := e.w.Write(e.scratch[:8])
	return err
}

// WriteInt8 writes a raw int8 (1 byte).
func (e *Encoder) WriteInt8(v int8) error {
	// #nosec G115 -- two's-complement wire representation.
	return e.WriteUint8(uint8(v))
}

// WriteInt16 writes a raw int16 (2 bytes, Big Endian).
func (e *Encoder) WriteInt16(v int16) error {
	// #nosec G115 -- two's-complement wire representation.
	return e.WriteUint16(uint16(v))
}

// WriteInt32 writes a raw int32 (4 bytes, Big Endian).
func (e *Encoder) WriteInt32(v int32) error {
	// #nosec G115 -- two's-complement wire representation.
	return e.WriteUint32(uint32(v))
}

// WriteInt64 writes a raw int64 (8 bytes, Big Endian).
func (e *Encoder) WriteInt64(v int64) error {
	// #nosec G115 -- two's-complement wire representation.
	return e.WriteUint64(uint64(v))
}

// WriteFloat32 writes a raw float32 (4 bytes, IEEE 754, Big Endian).
func (e *Encoder) WriteFloat32(v float32) error {
	return e.WriteUint32(math.Float32bits(v))
}

// WriteFloat64 writes a raw float64 (8 bytes, IEEE 754, Big Endian).
func (e *Encoder) WriteFloat64(v float64) error {
	return e.WriteUint64(math.Float64bits(v))
}

// WriteBytes writes a 4-byte length prefix followed by the byte slice payload.
func (e *Encoder) WriteBytes(b []byte) error {
	if uint64(len(b)) > math.MaxUint32 {
		return ErrPayloadTooLarge
	}
	// #nosec G115 -- bounds checked against math.MaxUint32 above.
	if err := e.WriteLength(uint32(len(b))); err != nil {
		return err
	}
	if len(b) > 0 {
		_, err := e.w.Write(b)
		return err
	}
	return nil
}

// WriteString writes a 4-byte length prefix followed by the string bytes.
func (e *Encoder) WriteString(s string) error {
	if uint64(len(s)) > math.MaxUint32 {
		return ErrPayloadTooLarge
	}
	// #nosec G115 -- bounds checked against math.MaxUint32 above.
	if err := e.WriteLength(uint32(len(s))); err != nil {
		return err
	}
	if len(s) > 0 {
		_, err := io.WriteString(e.w, s)
		return err
	}
	return nil
}

// WriteStrings writes a 4-byte element count followed by each length-prefixed string.
// For a full TLV frame compatible with SkipTLV, use WriteTLVStrings.
func (e *Encoder) WriteStrings(strs []string) error {
	if uint64(len(strs)) > math.MaxUint32 {
		return ErrPayloadTooLarge
	}
	// #nosec G115 -- bounds checked against math.MaxUint32 above.
	if err := e.WriteLength(uint32(len(strs))); err != nil {
		return err
	}
	for _, s := range strs {
		if err := e.WriteString(s); err != nil {
			return err
		}
	}
	return nil
}

// --- TLV HELPERS (High-level Encoder API) ---

// WriteTLVBytes writes a complete TLV frame (Tag + Length + Bytes).
func (e *Encoder) WriteTLVBytes(tag Tag, b []byte) error {
	if uint64(len(b)) > math.MaxUint32 {
		return ErrPayloadTooLarge
	}
	// #nosec G115 -- bounds checked against math.MaxUint32 above.
	e.putTLVHeader(tag, uint32(len(b)))
	if _, err := e.w.Write(e.scratch[:5]); err != nil {
		return err
	}
	if len(b) > 0 {
		_, err := e.w.Write(b)
		return err
	}
	return nil
}

// WriteTLVString writes a complete TLV frame (Tag + Length + String).
func (e *Encoder) WriteTLVString(tag Tag, s string) error {
	if uint64(len(s)) > math.MaxUint32 {
		return ErrPayloadTooLarge
	}
	// #nosec G115 -- bounds checked against math.MaxUint32 above.
	e.putTLVHeader(tag, uint32(len(s)))
	if _, err := e.w.Write(e.scratch[:5]); err != nil {
		return err
	}
	if len(s) > 0 {
		_, err := io.WriteString(e.w, s)
		return err
	}
	return nil
}

// WriteTLVTime writes a complete TLV frame (Tag + Length(12) + 12-byte Time).
func (e *Encoder) WriteTLVTime(tag Tag, t time.Time) error {
	e.putTLVHeader(tag, 12)
	putTime(e.scratch[5:17], t)
	_, err := e.w.Write(e.scratch[:17])
	return err
}

// WriteTLVBool writes a complete TLV frame (Tag + Length(1) + Bool).
func (e *Encoder) WriteTLVBool(tag Tag, v bool) error {
	e.putTLVHeader(tag, 1)
	e.scratch[5] = boolByte(v)
	_, err := e.w.Write(e.scratch[:6])
	return err
}

// WriteTLVUint8 writes a complete TLV frame (Tag + Length(1) + Uint8).
func (e *Encoder) WriteTLVUint8(tag Tag, v uint8) error {
	e.putTLVHeader(tag, 1)
	e.scratch[5] = v
	_, err := e.w.Write(e.scratch[:6])
	return err
}

// WriteTLVUint16 writes a complete TLV frame (Tag + Length(2) + Uint16).
func (e *Encoder) WriteTLVUint16(tag Tag, v uint16) error {
	e.putTLVHeader(tag, 2)
	binary.BigEndian.PutUint16(e.scratch[5:7], v)
	_, err := e.w.Write(e.scratch[:7])
	return err
}

// WriteTLVUint32 writes a complete TLV frame (Tag + Length(4) + Uint32).
func (e *Encoder) WriteTLVUint32(tag Tag, v uint32) error {
	e.putTLVHeader(tag, 4)
	binary.BigEndian.PutUint32(e.scratch[5:9], v)
	_, err := e.w.Write(e.scratch[:9])
	return err
}

// WriteTLVUint64 writes a complete TLV frame (Tag + Length(8) + Uint64).
func (e *Encoder) WriteTLVUint64(tag Tag, v uint64) error {
	e.putTLVHeader(tag, 8)
	binary.BigEndian.PutUint64(e.scratch[5:13], v)
	_, err := e.w.Write(e.scratch[:13])
	return err
}

// WriteTLVInt8 writes a complete TLV frame (Tag + Length(1) + Int8).
func (e *Encoder) WriteTLVInt8(tag Tag, v int8) error {
	// #nosec G115 -- two's-complement wire representation.
	return e.WriteTLVUint8(tag, uint8(v))
}

// WriteTLVInt16 writes a complete TLV frame (Tag + Length(2) + Int16).
func (e *Encoder) WriteTLVInt16(tag Tag, v int16) error {
	// #nosec G115 -- two's-complement wire representation.
	return e.WriteTLVUint16(tag, uint16(v))
}

// WriteTLVInt32 writes a complete TLV frame (Tag + Length(4) + Int32).
func (e *Encoder) WriteTLVInt32(tag Tag, v int32) error {
	// #nosec G115 -- two's-complement wire representation.
	return e.WriteTLVUint32(tag, uint32(v))
}

// WriteTLVInt64 writes a complete TLV frame (Tag + Length(8) + Int64).
func (e *Encoder) WriteTLVInt64(tag Tag, v int64) error {
	// #nosec G115 -- two's-complement wire representation.
	return e.WriteTLVUint64(tag, uint64(v))
}

// WriteTLVFloat32 writes a complete TLV frame (Tag + Length(4) + Float32).
func (e *Encoder) WriteTLVFloat32(tag Tag, v float32) error {
	return e.WriteTLVUint32(tag, math.Float32bits(v))
}

// WriteTLVFloat64 writes a complete TLV frame (Tag + Length(8) + Float64).
func (e *Encoder) WriteTLVFloat64(tag Tag, v float64) error {
	return e.WriteTLVUint64(tag, math.Float64bits(v))
}

// WriteTLVStrings writes a complete TLV frame for a string list:
// Tag + TotalPayloadByteLength + Count + each length-prefixed string.
// Putting TotalPayloadByteLength in the Length field guarantees SkipTLV compatibility.
func (e *Encoder) WriteTLVStrings(tag Tag, strs []string) error {
	if uint64(len(strs)) > math.MaxUint32 {
		return ErrPayloadTooLarge
	}
	totalBytes := uint64(4) // 4-byte list count
	for _, s := range strs {
		if uint64(len(s)) > math.MaxUint32 {
			return ErrPayloadTooLarge
		}
		totalBytes += 4 + uint64(len(s))
		if totalBytes > math.MaxUint32 {
			return ErrPayloadTooLarge
		}
	}

	// #nosec G115 -- totalBytes checked against math.MaxUint32 above.
	e.putTLVHeader(tag, uint32(totalBytes))
	if _, err := e.w.Write(e.scratch[:5]); err != nil {
		return err
	}
	return e.WriteStrings(strs)
}

// WriteNested encodes a nested TLV container using a lazily allocated, reusable buffer
// so the outer Length prefix is known without extra per-call heap allocations.
func (e *Encoder) WriteNested(tag Tag, fn func(*Encoder) error) error {
	if e.nestedBuf == nil {
		e.nestedBuf = new(bytes.Buffer)
		e.nestedEnc = NewEncoder(e.nestedBuf)
	} else {
		e.nestedBuf.Reset()
	}

	if err := fn(e.nestedEnc); err != nil {
		e.nestedBuf.Reset()
		return err
	}

	err := e.WriteTLVBytes(tag, e.nestedBuf.Bytes())
	if e.nestedBuf.Cap() > maxNestedBufRetain {
		e.nestedBuf = nil
		e.nestedEnc = nil
	} else {
		e.nestedBuf.Reset()
	}
	return err
}

// --- DECODER ---

// Decoder reads and validates TLV-encoded values from an io.Reader while enforcing
// configurable bounds against oversized payloads and Denial-of-Service attacks.
// A Decoder is not safe for concurrent use by multiple goroutines.
type Decoder struct {
	r             io.Reader
	scratch       [12]byte // Fits max raw primitive (Time = 12 bytes).
	MaxStringSize uint32
	MaxBytesSize  uint32
	MaxListCount  uint32
	MaxSkipSize   uint32
	// Separate LimitedReader fields prevent aliasing when Skip or ReadStringsPrefixed
	// executes inside an active ReadNested container.
	nestedLimit io.LimitedReader
	skipLimit   io.LimitedReader
	listLimit   io.LimitedReader
	nestedDec   *Decoder
}

// NewDecoder returns a new Decoder reading from r (which must be non-nil) with default safety limits.
func NewDecoder(r io.Reader) *Decoder {
	return &Decoder{
		r:             r,
		MaxStringSize: DefaultMaxStringSize,
		MaxBytesSize:  DefaultMaxBytesSize,
		MaxListCount:  DefaultMaxListCount,
		MaxSkipSize:   DefaultMaxSkipSize,
	}
}

// Reset reuses the Decoder with a new io.Reader while preserving configured limits.
func (d *Decoder) Reset(r io.Reader) {
	d.r = r
}

func (d *Decoder) readFixedLength(expected uint32, typeName string) error {
	length, err := d.ReadLength()
	if err != nil {
		return err
	}
	if length != expected {
		return fmt.Errorf("%w: %s length %d (expected %d)", ErrInvalidLength, typeName, length, expected)
	}
	return nil
}

// ReadTag reads a 1-byte Tag.
func (d *Decoder) ReadTag() (Tag, error) {
	if _, err := io.ReadFull(d.r, d.scratch[:1]); err != nil {
		return 0, err
	}
	return Tag(d.scratch[0]), nil
}

// ReadLength reads a 4-byte Big Endian uint32 length prefix.
func (d *Decoder) ReadLength() (uint32, error) {
	if _, err := io.ReadFull(d.r, d.scratch[:4]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(d.scratch[:4]), nil
}

// ReadTime decodes a raw 12-byte timestamp (without length prefix) and returns it in UTC.
// Use ReadTimePrefixed after ReadTag when decoding a WriteTLVTime frame.
func (d *Decoder) ReadTime() (time.Time, error) {
	if _, err := io.ReadFull(d.r, d.scratch[:12]); err != nil {
		return time.Time{}, err
	}
	// #nosec G115 -- two's-complement bit pattern restores signed Unix seconds.
	secs := int64(binary.BigEndian.Uint64(d.scratch[:8]))
	nanos := binary.BigEndian.Uint32(d.scratch[8:12])
	if nanos >= 1_000_000_000 {
		return time.Time{}, fmt.Errorf("%w: nanoseconds %d out of range", ErrInvalidTime, nanos)
	}
	return time.Unix(secs, int64(nanos)).UTC(), nil
}

// ReadBool reads a raw 1-byte boolean (without length prefix).
func (d *Decoder) ReadBool() (bool, error) {
	if _, err := io.ReadFull(d.r, d.scratch[:1]); err != nil {
		return false, err
	}
	return d.scratch[0] != 0x00, nil
}

// ReadUint8 reads a raw 1-byte uint8 (without length prefix).
func (d *Decoder) ReadUint8() (uint8, error) {
	if _, err := io.ReadFull(d.r, d.scratch[:1]); err != nil {
		return 0, err
	}
	return d.scratch[0], nil
}

// ReadUint16 reads a raw 2-byte Big Endian uint16 (without length prefix).
func (d *Decoder) ReadUint16() (uint16, error) {
	if _, err := io.ReadFull(d.r, d.scratch[:2]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(d.scratch[:2]), nil
}

// ReadUint32 reads a raw 4-byte Big Endian uint32 (without length prefix).
func (d *Decoder) ReadUint32() (uint32, error) {
	if _, err := io.ReadFull(d.r, d.scratch[:4]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(d.scratch[:4]), nil
}

// ReadUint64 reads a raw 8-byte Big Endian uint64 (without length prefix).
func (d *Decoder) ReadUint64() (uint64, error) {
	if _, err := io.ReadFull(d.r, d.scratch[:8]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(d.scratch[:8]), nil
}

// ReadInt8 reads a raw 1-byte int8 (without length prefix).
func (d *Decoder) ReadInt8() (int8, error) {
	v, err := d.ReadUint8()
	// #nosec G115 -- two's-complement wire representation.
	return int8(v), err
}

// ReadInt16 reads a raw 2-byte Big Endian int16 (without length prefix).
func (d *Decoder) ReadInt16() (int16, error) {
	v, err := d.ReadUint16()
	// #nosec G115 -- two's-complement wire representation.
	return int16(v), err
}

// ReadInt32 reads a raw 4-byte Big Endian int32 (without length prefix).
func (d *Decoder) ReadInt32() (int32, error) {
	v, err := d.ReadUint32()
	// #nosec G115 -- two's-complement wire representation.
	return int32(v), err
}

// ReadInt64 reads a raw 8-byte Big Endian int64 (without length prefix).
func (d *Decoder) ReadInt64() (int64, error) {
	v, err := d.ReadUint64()
	// #nosec G115 -- two's-complement wire representation.
	return int64(v), err
}

// ReadFloat32 reads a raw 4-byte IEEE 754 float32 (without length prefix).
func (d *Decoder) ReadFloat32() (float32, error) {
	v, err := d.ReadUint32()
	return math.Float32frombits(v), err
}

// ReadFloat64 reads a raw 8-byte IEEE 754 float64 (without length prefix).
func (d *Decoder) ReadFloat64() (float64, error) {
	v, err := d.ReadUint64()
	return math.Float64frombits(v), err
}

// --- PREFIXED DECODING (For ReadTag + switch-loop decoders) ---

// ReadTimePrefixed reads a Length prefix (must be 12) followed by a Time.
func (d *Decoder) ReadTimePrefixed() (time.Time, error) {
	if err := d.readFixedLength(12, "time"); err != nil {
		return time.Time{}, err
	}
	return d.ReadTime()
}

// ReadBoolPrefixed reads a Length prefix (must be 1) followed by a Bool.
func (d *Decoder) ReadBoolPrefixed() (bool, error) {
	if err := d.readFixedLength(1, "bool"); err != nil {
		return false, err
	}
	return d.ReadBool()
}

// ReadUint8Prefixed reads a Length prefix (must be 1) followed by a Uint8.
func (d *Decoder) ReadUint8Prefixed() (uint8, error) {
	if err := d.readFixedLength(1, "uint8"); err != nil {
		return 0, err
	}
	return d.ReadUint8()
}

// ReadUint16Prefixed reads a Length prefix (must be 2) followed by a Uint16.
func (d *Decoder) ReadUint16Prefixed() (uint16, error) {
	if err := d.readFixedLength(2, "uint16"); err != nil {
		return 0, err
	}
	return d.ReadUint16()
}

// ReadUint32Prefixed reads a Length prefix (must be 4) followed by a Uint32.
func (d *Decoder) ReadUint32Prefixed() (uint32, error) {
	if err := d.readFixedLength(4, "uint32"); err != nil {
		return 0, err
	}
	return d.ReadUint32()
}

// ReadUint64Prefixed reads a Length prefix (must be 8) followed by a Uint64.
func (d *Decoder) ReadUint64Prefixed() (uint64, error) {
	if err := d.readFixedLength(8, "uint64"); err != nil {
		return 0, err
	}
	return d.ReadUint64()
}

// ReadInt8Prefixed reads a Length prefix (must be 1) followed by an Int8.
func (d *Decoder) ReadInt8Prefixed() (int8, error) {
	if err := d.readFixedLength(1, "int8"); err != nil {
		return 0, err
	}
	return d.ReadInt8()
}

// ReadInt16Prefixed reads a Length prefix (must be 2) followed by an Int16.
func (d *Decoder) ReadInt16Prefixed() (int16, error) {
	if err := d.readFixedLength(2, "int16"); err != nil {
		return 0, err
	}
	return d.ReadInt16()
}

// ReadInt32Prefixed reads a Length prefix (must be 4) followed by an Int32.
func (d *Decoder) ReadInt32Prefixed() (int32, error) {
	if err := d.readFixedLength(4, "int32"); err != nil {
		return 0, err
	}
	return d.ReadInt32()
}

// ReadInt64Prefixed reads a Length prefix (must be 8) followed by an Int64.
func (d *Decoder) ReadInt64Prefixed() (int64, error) {
	if err := d.readFixedLength(8, "int64"); err != nil {
		return 0, err
	}
	return d.ReadInt64()
}

// ReadFloat32Prefixed reads a Length prefix (must be 4) followed by a Float32.
func (d *Decoder) ReadFloat32Prefixed() (float32, error) {
	if err := d.readFixedLength(4, "float32"); err != nil {
		return 0, err
	}
	return d.ReadFloat32()
}

// ReadFloat64Prefixed reads a Length prefix (must be 8) followed by a Float64.
func (d *Decoder) ReadFloat64Prefixed() (float64, error) {
	if err := d.readFixedLength(8, "float64"); err != nil {
		return 0, err
	}
	return d.ReadFloat64()
}

// ReadStringsPrefixed reads the total payload byte Length of a WriteTLVStrings frame,
// then decodes the bounded string list.
func (d *Decoder) ReadStringsPrefixed() ([]string, error) {
	payloadLen, err := d.ReadLength()
	if err != nil {
		return nil, err
	}
	return d.readBoundedStrings(payloadLen)
}

// ReadNestedBody reads a container Length prefix and runs fn with a bounded nested Decoder.
// Use this inside a ReadTag switch loop where the Tag has already been consumed.
func (d *Decoder) ReadNestedBody(fn func(*Decoder) error) error {
	length, err := d.ReadLength()
	if err != nil {
		return err
	}
	return d.readNestedPayload(length, fn)
}

// --- SECURE TLV DECODING (Tag verification + Validation) ---

// VerifyTag reads a Tag and returns *UnexpectedTagError (wrapping ErrInvalidTag) if it differs from expected.
func (d *Decoder) VerifyTag(expected Tag) error {
	tag, err := d.ReadTag()
	if err != nil {
		return err
	}
	if tag != expected {
		return &UnexpectedTagError{Expected: expected, Actual: tag}
	}
	return nil
}

// ReadTLVBool reads and verifies expected, checks Length == 1, and reads a Bool.
func (d *Decoder) ReadTLVBool(expected Tag) (bool, error) {
	if err := d.VerifyTag(expected); err != nil {
		return false, err
	}
	return d.ReadBoolPrefixed()
}

// ReadTLVUint8 reads and verifies expected, checks Length == 1, and reads a Uint8.
func (d *Decoder) ReadTLVUint8(expected Tag) (uint8, error) {
	if err := d.VerifyTag(expected); err != nil {
		return 0, err
	}
	return d.ReadUint8Prefixed()
}

// ReadTLVUint16 reads and verifies expected, checks Length == 2, and reads a Uint16.
func (d *Decoder) ReadTLVUint16(expected Tag) (uint16, error) {
	if err := d.VerifyTag(expected); err != nil {
		return 0, err
	}
	return d.ReadUint16Prefixed()
}

// ReadTLVUint32 reads and verifies expected, checks Length == 4, and reads a Uint32.
func (d *Decoder) ReadTLVUint32(expected Tag) (uint32, error) {
	if err := d.VerifyTag(expected); err != nil {
		return 0, err
	}
	return d.ReadUint32Prefixed()
}

// ReadTLVUint64 reads and verifies expected, checks Length == 8, and reads a Uint64.
func (d *Decoder) ReadTLVUint64(expected Tag) (uint64, error) {
	if err := d.VerifyTag(expected); err != nil {
		return 0, err
	}
	return d.ReadUint64Prefixed()
}

// ReadTLVInt8 reads and verifies expected, checks Length == 1, and reads an Int8.
func (d *Decoder) ReadTLVInt8(expected Tag) (int8, error) {
	if err := d.VerifyTag(expected); err != nil {
		return 0, err
	}
	return d.ReadInt8Prefixed()
}

// ReadTLVInt16 reads and verifies expected, checks Length == 2, and reads an Int16.
func (d *Decoder) ReadTLVInt16(expected Tag) (int16, error) {
	if err := d.VerifyTag(expected); err != nil {
		return 0, err
	}
	return d.ReadInt16Prefixed()
}

// ReadTLVInt32 reads and verifies expected, checks Length == 4, and reads an Int32.
func (d *Decoder) ReadTLVInt32(expected Tag) (int32, error) {
	if err := d.VerifyTag(expected); err != nil {
		return 0, err
	}
	return d.ReadInt32Prefixed()
}

// ReadTLVInt64 reads and verifies expected, checks Length == 8, and reads an Int64.
func (d *Decoder) ReadTLVInt64(expected Tag) (int64, error) {
	if err := d.VerifyTag(expected); err != nil {
		return 0, err
	}
	return d.ReadInt64Prefixed()
}

// ReadTLVFloat32 reads and verifies expected, checks Length == 4, and reads a Float32.
func (d *Decoder) ReadTLVFloat32(expected Tag) (float32, error) {
	if err := d.VerifyTag(expected); err != nil {
		return 0, err
	}
	return d.ReadFloat32Prefixed()
}

// ReadTLVFloat64 reads and verifies expected, checks Length == 8, and reads a Float64.
func (d *Decoder) ReadTLVFloat64(expected Tag) (float64, error) {
	if err := d.VerifyTag(expected); err != nil {
		return 0, err
	}
	return d.ReadFloat64Prefixed()
}

// ReadTLVString reads and verifies expected, then reads a length-prefixed String.
func (d *Decoder) ReadTLVString(expected Tag) (string, error) {
	if err := d.VerifyTag(expected); err != nil {
		return "", err
	}
	return d.ReadString()
}

// ReadTLVBytes reads and verifies expected, then reads a length-prefixed Byte slice.
func (d *Decoder) ReadTLVBytes(expected Tag) ([]byte, error) {
	if err := d.VerifyTag(expected); err != nil {
		return nil, err
	}
	return d.ReadBytes()
}

// ReadTLVBytesInto reads and verifies expected, reads Length, validates MaxBytesSize and len(buf),
// and copies payload bytes directly into buf without heap allocations.
// If len(buf) < length, it returns *ShortBufferError (wrapping ErrShortBuffer) with Required set so
// the caller can resize and recover with ReadBytesInto(shortErr.Required, biggerBuf).
func (d *Decoder) ReadTLVBytesInto(expected Tag, buf []byte) (int, error) {
	if err := d.VerifyTag(expected); err != nil {
		return 0, err
	}
	length, err := d.ReadLength()
	if err != nil {
		return 0, err
	}
	return d.ReadBytesInto(length, buf)
}

// ReadTLVTime reads and verifies expected, checks Length == 12, and reads a Time.
func (d *Decoder) ReadTLVTime(expected Tag) (time.Time, error) {
	if err := d.VerifyTag(expected); err != nil {
		return time.Time{}, err
	}
	return d.ReadTimePrefixed()
}

// ReadTLVStrings reads and verifies expected, then reads a TLV-framed string list.
func (d *Decoder) ReadTLVStrings(expected Tag) ([]string, error) {
	if err := d.VerifyTag(expected); err != nil {
		return nil, err
	}
	return d.ReadStringsPrefixed()
}

// ReadNested handles a TLV container (a TLV whose body contains nested TLVs).
// It verifies expected, reads Length, bounds a reusable nested Decoder to the container body,
// runs fn, and drains any unread trailing bytes (bounded by MaxSkipSize).
func (d *Decoder) ReadNested(expected Tag, fn func(*Decoder) error) error {
	if err := d.VerifyTag(expected); err != nil {
		return err
	}
	return d.ReadNestedBody(fn)
}

func (d *Decoder) readNestedPayload(length uint32, fn func(*Decoder) error) error {
	if d.nestedDec == nil {
		d.nestedDec = &Decoder{}
	}
	nd := d.nestedDec

	nd.nestedLimit.R = d.r
	nd.nestedLimit.N = int64(length)

	nd.r = &nd.nestedLimit
	nd.MaxStringSize = d.MaxStringSize
	nd.MaxBytesSize = d.MaxBytesSize
	nd.MaxListCount = d.MaxListCount
	nd.MaxSkipSize = d.MaxSkipSize

	if err := fn(nd); err != nil {
		return err
	}

	remaining := nd.nestedLimit.N
	if remaining == 0 {
		return nil
	}
	if remaining > int64(d.MaxSkipSize) {
		return fmt.Errorf("%w: nested unread %d > %d", ErrPayloadTooLarge, remaining, d.MaxSkipSize)
	}
	// #nosec G115 -- remaining > 0 and <= d.MaxSkipSize (uint32).
	if err := d.Skip(uint32(remaining)); err != nil {
		if errors.Is(err, io.EOF) {
			return fmt.Errorf("%w: nested container truncated (%d bytes unread)", io.ErrUnexpectedEOF, remaining)
		}
		return err
	}
	return nil
}

// ReadBytes reads a 4-byte Length prefix and returns a freshly allocated byte slice ([]byte{} when length == 0).
func (d *Decoder) ReadBytes() ([]byte, error) {
	length, err := d.ReadLength()
	if err != nil {
		return nil, err
	}
	if length == 0 {
		return []byte{}, nil
	}
	if length > d.MaxBytesSize {
		return nil, fmt.Errorf("%w: %d > %d", ErrPayloadTooLarge, length, d.MaxBytesSize)
	}
	if uint64(length) > uint64(math.MaxInt) {
		return nil, fmt.Errorf("%w: %d exceeds max int", ErrPayloadTooLarge, length)
	}

	buf := make([]byte, length)
	if _, err := io.ReadFull(d.r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// ReadBytesInto validates MaxBytesSize and len(buf), then reads strictly length bytes into buf.
// Callers must read length beforehand (for example via ReadLength) and pass a slice whose len(buf) >= length.
// It returns the actual number of bytes copied into buf and any error.
func (d *Decoder) ReadBytesInto(length uint32, buf []byte) (int, error) {
	if length > d.MaxBytesSize {
		return 0, fmt.Errorf("%w: %d > %d", ErrPayloadTooLarge, length, d.MaxBytesSize)
	}
	if uint64(len(buf)) < uint64(length) {
		return 0, &ShortBufferError{Required: length, Available: len(buf)}
	}
	if length == 0 {
		return 0, nil
	}
	return io.ReadFull(d.r, buf[:length])
}

// ReadString reads a 4-byte Length prefix and returns the decoded string using unsafe.String
// to avoid copying the allocated backing byte buffer.
func (d *Decoder) ReadString() (string, error) {
	return d.readStringFrom(d.r)
}

func (d *Decoder) readStringFrom(r io.Reader) (string, error) {
	if _, err := io.ReadFull(r, d.scratch[:4]); err != nil {
		return "", err
	}
	length := binary.BigEndian.Uint32(d.scratch[:4])
	if length == 0 {
		return "", nil
	}
	if length > d.MaxStringSize {
		return "", fmt.Errorf("%w: string %d > %d", ErrPayloadTooLarge, length, d.MaxStringSize)
	}
	if uint64(length) > uint64(math.MaxInt) {
		return "", fmt.Errorf("%w: string %d exceeds max int", ErrPayloadTooLarge, length)
	}

	buf := make([]byte, length)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", err
	}

	// #nosec G103 -- buf is freshly allocated, never mutated after ReadFull, and not retained elsewhere.
	return unsafe.String(unsafe.SliceData(buf), length), nil
}

// ReadStrings decodes a raw count-prefixed list of strings (matching WriteStrings).
// Returns nil when count == 0; callers should check len(strs) == 0.
func (d *Decoder) ReadStrings() ([]string, error) {
	count, err := d.ReadLength()
	if err != nil {
		return nil, err
	}
	return d.readStringsBody(d.r, count)
}

func (d *Decoder) readBoundedStrings(payloadLen uint32) ([]string, error) {
	if payloadLen < 4 {
		return nil, fmt.Errorf("%w: string list length %d (expected >= 4)", ErrInvalidLength, payloadLen)
	}
	if d.MaxListCount > 0 {
		perElem := uint64(4) + uint64(d.MaxStringSize)
		if perElem <= (math.MaxUint64-4)/uint64(d.MaxListCount) {
			maxAllowed := uint64(4) + uint64(d.MaxListCount)*perElem
			if uint64(payloadLen) > maxAllowed {
				return nil, fmt.Errorf("%w: string list %d > %d", ErrPayloadTooLarge, payloadLen, maxAllowed)
			}
		}
	}

	d.listLimit.R = d.r
	d.listLimit.N = int64(payloadLen)

	if _, err := io.ReadFull(&d.listLimit, d.scratch[:4]); err != nil {
		return nil, err
	}
	count := binary.BigEndian.Uint32(d.scratch[:4])
	if uint64(count)*4 > uint64(payloadLen-4) {
		return nil, fmt.Errorf("%w: list count %d cannot fit in %d bytes", ErrInvalidLength, count, payloadLen)
	}

	strs, err := d.readStringsBody(&d.listLimit, count)
	if err != nil {
		return nil, err
	}
	if d.listLimit.N > 0 {
		return nil, fmt.Errorf("%w: string list has %d trailing bytes", ErrInvalidLength, d.listLimit.N)
	}
	return strs, nil
}

func (d *Decoder) readStringsBody(r io.Reader, count uint32) ([]string, error) {
	if count == 0 {
		return nil, nil
	}
	if count > d.MaxListCount {
		return nil, fmt.Errorf("%w: %d > %d", ErrListTooLarge, count, d.MaxListCount)
	}
	if uint64(count) > uint64(math.MaxInt) {
		return nil, fmt.Errorf("%w: %d exceeds max int", ErrListTooLarge, count)
	}

	prealloc := count
	if prealloc > maxListPrealloc {
		prealloc = maxListPrealloc
	}
	strs := make([]string, 0, prealloc)
	for i := uint32(0); i < count; i++ {
		s, err := d.readStringFrom(r)
		if err != nil {
			return nil, err
		}
		strs = append(strs, s)
	}
	return strs, nil
}

// Skip discards n bytes from the stream without allocating.
// Uses an io.Seeker fast-path (with explicit EOF validation) when supported, falling back
// to an embedded io.LimitedReader on network or pipe streams.
func (d *Decoder) Skip(n uint32) error {
	if n > d.MaxSkipSize {
		return fmt.Errorf("%w: skip %d > %d", ErrPayloadTooLarge, n, d.MaxSkipSize)
	}
	if n == 0 {
		return nil
	}

	if seeker, ok := d.r.(io.Seeker); ok {
		if cur, err := seeker.Seek(0, io.SeekCurrent); err == nil {
			end, err := seeker.Seek(0, io.SeekEnd)
			if err != nil {
				return err
			}
			if end-cur < int64(n) {
				return io.EOF
			}
			_, err = seeker.Seek(cur+int64(n), io.SeekStart)
			return err
		}
	}

	d.skipLimit.R = d.r
	d.skipLimit.N = int64(n)
	written, err := io.Copy(io.Discard, &d.skipLimit)
	if err == nil && written < int64(n) {
		return io.EOF
	}
	return err
}

// SkipTLV reads a 4-byte Length prefix and skips that many payload bytes.
func (d *Decoder) SkipTLV() error {
	length, err := d.ReadLength()
	if err != nil {
		return err
	}
	return d.Skip(length)
}
