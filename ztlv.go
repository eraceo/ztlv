package ztlv

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"time"
	"unsafe"
)

var (
	ErrPayloadTooLarge = errors.New("ztlv: payload exceeds configured limit")
	ErrListTooLarge    = errors.New("ztlv: list count exceeds configured limit")
	ErrShortBuffer     = errors.New("ztlv: buffer too short")
	ErrInvalidTag      = errors.New("ztlv: invalid tag found")
	ErrInvalidLength   = errors.New("ztlv: invalid length for type")
)

const (
	// Default safety limits
	DefaultMaxStringSize = 1 << 20  // 1 MB
	DefaultMaxBytesSize  = 10 << 20 // 10 MB
	DefaultMaxListCount  = 1000
)

type Tag byte

// --- ERROR HANDLING ---

// UnexpectedTagError is returned when the read tag does not match the expected tag.
type UnexpectedTagError struct {
	Expected Tag
	Actual   Tag
}

func (e *UnexpectedTagError) Error() string {
	return fmt.Sprintf("ztlv: expected tag 0x%02X, got 0x%02X", e.Expected, e.Actual)
}

// Encoder remains lightweight. Allocations are primarily handled by the underlying Writer.
type Encoder struct {
	w       io.Writer
	scratch [12]byte // Sized to support Time encoding (8+4 bytes)
}

func NewEncoder(w io.Writer) *Encoder {
	return &Encoder{w: w}
}

func (e *Encoder) WriteTag(tag Tag) error {
	e.scratch[0] = byte(tag)
	_, err := e.w.Write(e.scratch[:1])
	return err
}

func (e *Encoder) WriteLength(length uint32) error {
	binary.BigEndian.PutUint32(e.scratch[:4], length)
	_, err := e.w.Write(e.scratch[:4])
	return err
}

// WriteTime encodes a timestamp robustly: compatible with all dates, avoids Year 2038 issues.
func (e *Encoder) WriteTime(t time.Time) error {
	// Store Seconds (int64) + Nanoseconds (uint32)
	binary.BigEndian.PutUint64(e.scratch[:8], uint64(t.Unix()))
	binary.BigEndian.PutUint32(e.scratch[8:12], uint32(t.Nanosecond()))
	_, err := e.w.Write(e.scratch[:12])
	return err
}

// WriteBool writes a boolean (1 byte). 0x01 for true, 0x00 for false.
func (e *Encoder) WriteBool(v bool) error {
	var b byte
	if v {
		b = 0x01
	}
	e.scratch[0] = b
	_, err := e.w.Write(e.scratch[:1])
	return err
}

// WriteUint8 writes a uint8 (1 byte).
func (e *Encoder) WriteUint8(v uint8) error {
	e.scratch[0] = v
	_, err := e.w.Write(e.scratch[:1])
	return err
}

// WriteUint16 writes a uint16 (2 bytes, Big Endian).
func (e *Encoder) WriteUint16(v uint16) error {
	binary.BigEndian.PutUint16(e.scratch[:2], v)
	_, err := e.w.Write(e.scratch[:2])
	return err
}

// WriteUint32 writes a uint32 (4 bytes, Big Endian).
func (e *Encoder) WriteUint32(v uint32) error {
	binary.BigEndian.PutUint32(e.scratch[:4], v)
	_, err := e.w.Write(e.scratch[:4])
	return err
}

// WriteUint64 writes a uint64 (8 bytes, Big Endian).
func (e *Encoder) WriteUint64(v uint64) error {
	binary.BigEndian.PutUint64(e.scratch[:8], v)
	_, err := e.w.Write(e.scratch[:8])
	return err
}

// WriteInt64 writes an int64 (8 bytes, Big Endian).
func (e *Encoder) WriteInt64(v int64) error {
	return e.WriteUint64(uint64(v))
}

// WriteFloat64 writes a float64 (8 bytes, IEEE 754, Big Endian).
func (e *Encoder) WriteFloat64(v float64) error {
	return e.WriteUint64(math.Float64bits(v))
}

// WriteBytes writes a standard byte slice.
func (e *Encoder) WriteBytes(b []byte) error {
	if len(b) > math.MaxUint32 {
		return ErrPayloadTooLarge
	}
	// #nosec G115
	if err := e.WriteLength(uint32(len(b))); err != nil {
		return err
	}
	if len(b) > 0 {
		_, err := e.w.Write(b)
		return err
	}
	return nil
}

func (e *Encoder) WriteString(s string) error {
	if len(s) > math.MaxUint32 {
		return ErrPayloadTooLarge
	}
	// #nosec G115
	if err := e.WriteLength(uint32(len(s))); err != nil {
		return err
	}
	if len(s) > 0 {
		_, err := io.WriteString(e.w, s)
		return err
	}
	return nil
}

func (e *Encoder) WriteStrings(strs []string) error {
	if len(strs) > math.MaxUint32 {
		return ErrListTooLarge
	}
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

// --- TLV Helpers (High-level API) ---

// WriteTLVBytes writes a Tag, then the Length of the bytes, then the Bytes themselves.
func (e *Encoder) WriteTLVBytes(tag Tag, b []byte) error {
	if err := e.WriteTag(tag); err != nil {
		return err
	}
	return e.WriteBytes(b)
}

// WriteTLVString writes a Tag, then the Length of the string, then the String itself.
func (e *Encoder) WriteTLVString(tag Tag, s string) error {
	if err := e.WriteTag(tag); err != nil {
		return err
	}
	return e.WriteString(s)
}

// WriteTLVTime writes a Tag, then the Length of the time (12 bytes), then the Time itself.
func (e *Encoder) WriteTLVTime(tag Tag, t time.Time) error {
	if err := e.WriteTag(tag); err != nil {
		return err
	}
	// Time is always 12 bytes (8 sec + 4 nano)
	if err := e.WriteLength(12); err != nil {
		return err
	}
	return e.WriteTime(t)
}

// WriteTLVBool writes a Tag, Length (1), then the Bool (1 byte).
func (e *Encoder) WriteTLVBool(tag Tag, v bool) error {
	if err := e.WriteTag(tag); err != nil {
		return err
	}
	if err := e.WriteLength(1); err != nil {
		return err
	}
	return e.WriteBool(v)
}

// WriteTLVUint8 writes a Tag, Length (1), then the Uint8 (1 byte).
func (e *Encoder) WriteTLVUint8(tag Tag, v uint8) error {
	if err := e.WriteTag(tag); err != nil {
		return err
	}
	if err := e.WriteLength(1); err != nil {
		return err
	}
	return e.WriteUint8(v)
}

// WriteTLVUint16 writes a Tag, Length (2), then the Uint16 (2 bytes).
func (e *Encoder) WriteTLVUint16(tag Tag, v uint16) error {
	if err := e.WriteTag(tag); err != nil {
		return err
	}
	if err := e.WriteLength(2); err != nil {
		return err
	}
	return e.WriteUint16(v)
}

// WriteTLVUint32 writes a Tag, Length (4), then the Uint32 (4 bytes).
func (e *Encoder) WriteTLVUint32(tag Tag, v uint32) error {
	if err := e.WriteTag(tag); err != nil {
		return err
	}
	if err := e.WriteLength(4); err != nil {
		return err
	}
	return e.WriteUint32(v)
}

// WriteTLVUint64 writes a Tag, Length (8), then the Uint64 (8 bytes).
func (e *Encoder) WriteTLVUint64(tag Tag, v uint64) error {
	if err := e.WriteTag(tag); err != nil {
		return err
	}
	if err := e.WriteLength(8); err != nil {
		return err
	}
	return e.WriteUint64(v)
}

// WriteTLVInt64 writes a Tag, Length (8), then the Int64 (8 bytes).
func (e *Encoder) WriteTLVInt64(tag Tag, v int64) error {
	return e.WriteTLVUint64(tag, uint64(v))
}

// WriteTLVFloat64 writes a Tag, Length (8), then the Float64 (8 bytes).
func (e *Encoder) WriteTLVFloat64(tag Tag, v float64) error {
	return e.WriteTLVUint64(tag, math.Float64bits(v))
}

// --- DECODER ---

type Decoder struct {
	r             io.Reader
	scratch       [12]byte // Sized for Time decoding
	MaxStringSize uint32
	MaxBytesSize  uint32
	MaxListCount  uint32
}

func NewDecoder(r io.Reader) *Decoder {
	return &Decoder{
		r:             r,
		MaxStringSize: DefaultMaxStringSize,
		MaxBytesSize:  DefaultMaxBytesSize,
		MaxListCount:  DefaultMaxListCount,
	}
}

func (d *Decoder) ReadTag() (Tag, error) {
	if _, err := io.ReadFull(d.r, d.scratch[:1]); err != nil {
		return 0, err
	}
	return Tag(d.scratch[0]), nil
}

func (d *Decoder) ReadLength() (uint32, error) {
	if _, err := io.ReadFull(d.r, d.scratch[:4]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(d.scratch[:4]), nil
}

// ReadTime decodes a robust timestamp (Seconds + Nanoseconds).
// Note: This reads strictly 12 bytes. It does NOT read a length prefix.
// Use ReadTimePrefixed if you are using standard TLV (WriteTLVTime).
func (d *Decoder) ReadTime() (time.Time, error) {
	if _, err := io.ReadFull(d.r, d.scratch[:12]); err != nil {
		return time.Time{}, err
	}
	secs := int64(binary.BigEndian.Uint64(d.scratch[:8]))
	nanos := int64(binary.BigEndian.Uint32(d.scratch[8:12])) // Cast to int64 for time.Unix
	return time.Unix(secs, nanos).UTC(), nil                 // Always return in UTC by default
}

// ReadTimePrefixed reads a Length prefix, verifies it is 12, and then reads the Time.
// This is the secure counterpart to WriteTLVTime.
func (d *Decoder) ReadTimePrefixed() (time.Time, error) {
	length, err := d.ReadLength()
	if err != nil {
		return time.Time{}, err
	}
	if length != 12 {
		return time.Time{}, fmt.Errorf("%w: invalid time length %d (expected 12)", ErrInvalidLength, length)
	}
	return d.ReadTime()
}

// ReadBool reads a boolean (1 byte).
func (d *Decoder) ReadBool() (bool, error) {
	if _, err := io.ReadFull(d.r, d.scratch[:1]); err != nil {
		return false, err
	}
	return d.scratch[0] != 0x00, nil
}

// ReadUint8 reads a uint8 (1 byte).
func (d *Decoder) ReadUint8() (uint8, error) {
	if _, err := io.ReadFull(d.r, d.scratch[:1]); err != nil {
		return 0, err
	}
	return d.scratch[0], nil
}

// ReadUint16 reads a uint16 (2 bytes, Big Endian).
func (d *Decoder) ReadUint16() (uint16, error) {
	if _, err := io.ReadFull(d.r, d.scratch[:2]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(d.scratch[:2]), nil
}

// ReadUint32 reads a uint32 (4 bytes, Big Endian).
func (d *Decoder) ReadUint32() (uint32, error) {
	if _, err := io.ReadFull(d.r, d.scratch[:4]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(d.scratch[:4]), nil
}

// ReadUint64 reads a uint64 (8 bytes, Big Endian).
func (d *Decoder) ReadUint64() (uint64, error) {
	if _, err := io.ReadFull(d.r, d.scratch[:8]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(d.scratch[:8]), nil
}

// ReadInt64 reads an int64 (8 bytes, Big Endian).
func (d *Decoder) ReadInt64() (int64, error) {
	v, err := d.ReadUint64()
	return int64(v), err
}

// ReadFloat64 reads a float64 (8 bytes, IEEE 754, Big Endian).
func (d *Decoder) ReadFloat64() (float64, error) {
	v, err := d.ReadUint64()
	return math.Float64frombits(v), err
}

// --- SECURE DECODING (Typed Errors & Validation) ---

// VerifyTag reads a Tag and returns an error if it does not match the expected Tag.
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

// ReadTLVBool reads a Tag, verifies it, reads Length (must be 1), then reads Bool.
func (d *Decoder) ReadTLVBool(expected Tag) (bool, error) {
	if err := d.VerifyTag(expected); err != nil {
		return false, err
	}
	length, err := d.ReadLength()
	if err != nil {
		return false, err
	}
	if length != 1 {
		return false, fmt.Errorf("%w: bool length %d (expected 1)", ErrInvalidLength, length)
	}
	return d.ReadBool()
}

// ReadTLVUint8 reads a Tag, verifies it, reads Length (must be 1), then reads Uint8.
func (d *Decoder) ReadTLVUint8(expected Tag) (uint8, error) {
	if err := d.VerifyTag(expected); err != nil {
		return 0, err
	}
	length, err := d.ReadLength()
	if err != nil {
		return 0, err
	}
	if length != 1 {
		return 0, fmt.Errorf("%w: uint8 length %d (expected 1)", ErrInvalidLength, length)
	}
	return d.ReadUint8()
}

// ReadTLVUint16 reads a Tag, verifies it, reads Length (must be 2), then reads Uint16.
func (d *Decoder) ReadTLVUint16(expected Tag) (uint16, error) {
	if err := d.VerifyTag(expected); err != nil {
		return 0, err
	}
	length, err := d.ReadLength()
	if err != nil {
		return 0, err
	}
	if length != 2 {
		return 0, fmt.Errorf("%w: uint16 length %d (expected 2)", ErrInvalidLength, length)
	}
	return d.ReadUint16()
}

// ReadTLVUint32 reads a Tag, verifies it, reads Length (must be 4), then reads Uint32.
func (d *Decoder) ReadTLVUint32(expected Tag) (uint32, error) {
	if err := d.VerifyTag(expected); err != nil {
		return 0, err
	}
	length, err := d.ReadLength()
	if err != nil {
		return 0, err
	}
	if length != 4 {
		return 0, fmt.Errorf("%w: uint32 length %d (expected 4)", ErrInvalidLength, length)
	}
	return d.ReadUint32()
}

// ReadTLVUint64 reads a Tag, verifies it, reads Length (must be 8), then reads Uint64.
func (d *Decoder) ReadTLVUint64(expected Tag) (uint64, error) {
	if err := d.VerifyTag(expected); err != nil {
		return 0, err
	}
	length, err := d.ReadLength()
	if err != nil {
		return 0, err
	}
	if length != 8 {
		return 0, fmt.Errorf("%w: uint64 length %d (expected 8)", ErrInvalidLength, length)
	}
	return d.ReadUint64()
}

// ReadTLVInt64 reads a Tag, verifies it, reads Length (must be 8), then reads Int64.
func (d *Decoder) ReadTLVInt64(expected Tag) (int64, error) {
	v, err := d.ReadTLVUint64(expected)
	return int64(v), err
}

// ReadTLVFloat64 reads a Tag, verifies it, reads Length (must be 8), then reads Float64.
func (d *Decoder) ReadTLVFloat64(expected Tag) (float64, error) {
	v, err := d.ReadTLVUint64(expected)
	return math.Float64frombits(v), err
}

// ReadTLVString reads a Tag, verifies it, reads Length, then reads String.
func (d *Decoder) ReadTLVString(expected Tag) (string, error) {
	if err := d.VerifyTag(expected); err != nil {
		return "", err
	}
	return d.ReadString()
}

// ReadTLVBytes reads a Tag, verifies it, reads Length, then reads Bytes.
func (d *Decoder) ReadTLVBytes(expected Tag) ([]byte, error) {
	if err := d.VerifyTag(expected); err != nil {
		return nil, err
	}
	return d.ReadBytes()
}

// ReadTLVBytesInto reads a Tag, verifies it, reads Length, checks buffer size,
// and reads bytes directly into the provided buffer.
// This is the most efficient and secure way to read bytes without allocation.
func (d *Decoder) ReadTLVBytesInto(expected Tag, buf []byte) (int, error) {
	if err := d.VerifyTag(expected); err != nil {
		return 0, err
	}
	length, err := d.ReadLength()
	if err != nil {
		return 0, err
	}
	if uint32(len(buf)) < length {
		return 0, ErrShortBuffer
	}
	// Read directly into the user-provided buffer
	_, err = io.ReadFull(d.r, buf[:length])
	return int(length), err
}

// ReadTLVTime reads a Tag, verifies it, reads Length (must be 12), then reads Time.
func (d *Decoder) ReadTLVTime(expected Tag) (time.Time, error) {
	if err := d.VerifyTag(expected); err != nil {
		return time.Time{}, err
	}
	return d.ReadTimePrefixed()
}

// ReadNested handles a TLV container (a TLV that contains other TLVs).
// It reads the Tag and Length, creates a limited Decoder for the body, and executes the callback.
//
// Security: The nested decoder is strictly limited to the container's length.
// It prevents reading past the container boundary.
//
// Usage:
//
//	err := dec.ReadNested(TagUser, func(d *ztlv.Decoder) error {
//	    name, _ := d.ReadTLVString(TagName)
//	    age, _ := d.ReadTLVUint8(TagAge)
//	    return nil
//	})
func (d *Decoder) ReadNested(expected Tag, fn func(*Decoder) error) error {
	if err := d.VerifyTag(expected); err != nil {
		return err
	}
	length, err := d.ReadLength()
	if err != nil {
		return err
	}

	// Create a limited reader that allows reading ONLY 'length' bytes
	limitReader := io.LimitReader(d.r, int64(length))

	// Create a new decoder for this limited scope
	nestedDec := NewDecoder(limitReader)
	// Inherit configuration from parent (critical fix)
	nestedDec.MaxStringSize = d.MaxStringSize
	nestedDec.MaxBytesSize = d.MaxBytesSize
	nestedDec.MaxListCount = d.MaxListCount

	if err := fn(nestedDec); err != nil {
		return err
	}

	// Ensure we drain any unread bytes from the nested structure
	// so the parent decoder is correctly positioned for the next TLV.
	// io.LimitReader stops at EOF when limit is reached.
	// If the user didn't read everything, we must skip the rest.
	_, err = io.Copy(io.Discard, limitReader)
	return err
}

// ReadBytes is optimized for a single allocation.
// It is "Low Alloc" but safe (returns a clean copy).
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

	buf := make([]byte, length)
	if _, err := io.ReadFull(d.r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// ReadBytesInto enables "Zero Alloc" scenarios if the caller reuses their buffer.
// Warning: This method reads strictly 'length' bytes. It does NOT read the length prefix itself.
// The caller must have read the length beforehand (e.g. via ReadLength()).
// It returns the number of bytes read (which is always equal to length on success) and any error.
func (d *Decoder) ReadBytesInto(length uint32, buf []byte) (int, error) {
	if uint32(len(buf)) < length {
		return 0, ErrShortBuffer
	}
	// Read directly into the user-provided buffer
	_, err := io.ReadFull(d.r, buf[:length])
	return int(length), err
}

// ReadString uses "unsafe" optimizations (Go 1.20+) to reduce allocations.
func (d *Decoder) ReadString() (string, error) {
	length, err := d.ReadLength()
	if err != nil {
		return "", err
	}
	if length == 0 {
		return "", nil
	}
	if length > d.MaxStringSize {
		return "", fmt.Errorf("%w: string %d > %d", ErrPayloadTooLarge, length, d.MaxStringSize)
	}

	// Allocate the byte buffer once
	buf := make([]byte, length)
	if _, err := io.ReadFull(d.r, buf); err != nil {
		return "", err
	}

	// unsafe.String avoids a COPY (byte->string).
	// Note: 'buf' technically escapes to the heap because the string is returned,
	// but we save the CPU cost of copying the data into a new string structure.
	return unsafe.String(unsafe.SliceData(buf), length), nil
}

func (d *Decoder) ReadStrings() ([]string, error) {
	count, err := d.ReadLength()
	if err != nil {
		return nil, err
	}
	if count == 0 {
		// Consistent with ReadBytes: return empty slice, not nil
		return []string{}, nil
	}
	if count > d.MaxListCount {
		return nil, fmt.Errorf("%w: %d > %d", ErrListTooLarge, count, d.MaxListCount)
	}

	strs := make([]string, count)
	for i := uint32(0); i < count; i++ {
		s, err := d.ReadString()
		if err != nil {
			return nil, err
		}
		strs[i] = s
	}
	return strs, nil
}

func (d *Decoder) Skip(n uint32) error {
	_, err := io.CopyN(io.Discard, d.r, int64(n))
	return err
}
