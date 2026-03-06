package ztlv_test

import (
	"bytes"
	"encoding/binary"
	"io"
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eraceo/ztlv"
)

// --- UNIT & FUNCTIONAL TESTS ---

func TestTagAndLength(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	enc := ztlv.NewEncoder(&buf)
	dec := ztlv.NewDecoder(&buf)

	// Write two tags (min and max values) and verify round-trip
	require.NoError(t, enc.WriteTag(0x01))
	require.NoError(t, enc.WriteTag(0xFF))

	tag, err := dec.ReadTag()
	require.NoError(t, err)
	assert.Equal(t, ztlv.Tag(0x01), tag)

	tag, err = dec.ReadTag()
	require.NoError(t, err)
	assert.Equal(t, ztlv.Tag(0xFF), tag)

	// Test boundary lengths: 0, an arbitrary value, and MaxUint32
	buf.Reset()
	require.NoError(t, enc.WriteLength(0))
	require.NoError(t, enc.WriteLength(42))
	require.NoError(t, enc.WriteLength(4294967295)) // MaxUint32

	length, err := dec.ReadLength()
	require.NoError(t, err)
	assert.Equal(t, uint32(0), length)

	length, err = dec.ReadLength()
	require.NoError(t, err)
	assert.Equal(t, uint32(42), length)

	length, err = dec.ReadLength()
	require.NoError(t, err)
	assert.Equal(t, uint32(4294967295), length)
}

func TestBytes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    []byte
		expected []byte
	}{
		{"Normal bytes", []byte{0xDE, 0xAD, 0xBE, 0xEF}, []byte{0xDE, 0xAD, 0xBE, 0xEF}},
		// ReadBytes returns []byte{} (non-nil) for empty/nil input — safe for callers,
		// avoids surprising nil pointer dereferences downstream.
		{"Empty bytes", []byte{}, []byte{}},
		{"Nil bytes", nil, []byte{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			enc := ztlv.NewEncoder(&buf)
			dec := ztlv.NewDecoder(&buf)

			require.NoError(t, enc.WriteBytes(tt.input))

			actual, err := dec.ReadBytes()
			require.NoError(t, err)
			assert.Equal(t, tt.expected, actual)
		})
	}
}

func TestReadBytesInto_ZeroAlloc(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	enc := ztlv.NewEncoder(&buf)
	dec := ztlv.NewDecoder(&buf)

	data := []byte{0xCA, 0xFE, 0xBA, 0xBE}
	require.NoError(t, enc.WriteBytes(data))

	// Step 1: Read the length prefix manually (caller's responsibility)
	length, err := dec.ReadLength()
	require.NoError(t, err)
	assert.Equal(t, uint32(4), length)

	// Step 2: Read payload into a pre-allocated buffer (zero allocation path)
	myBuf := make([]byte, 4)
	n, err := dec.ReadBytesInto(length, myBuf)
	require.NoError(t, err)
	assert.Equal(t, 4, n)
	assert.Equal(t, data, myBuf)

	// Error case: buffer too small.
	// IMPORTANT: ReadBytesInto fails fast WITHOUT consuming bytes from the reader,
	// so the caller can retry with a larger buffer — stream integrity is preserved.
	buf.Reset()
	require.NoError(t, enc.WriteBytes(data))
	length, err = dec.ReadLength()
	require.NoError(t, err)

	smallBuf := make([]byte, 2) // Too small
	_, err = dec.ReadBytesInto(length, smallBuf)
	require.ErrorIs(t, err, ztlv.ErrShortBuffer)

	// Retry with the correct size — data is still available in the reader.
	bigBuf := make([]byte, 4)
	n, err = dec.ReadBytesInto(length, bigBuf)
	require.NoError(t, err)
	assert.Equal(t, 4, n)
	assert.Equal(t, data, bigBuf)
}

func TestReadTLVBytesInto(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	enc := ztlv.NewEncoder(&buf)
	dec := ztlv.NewDecoder(&buf)

	data := []byte{0x01, 0x02, 0x03}
	require.NoError(t, enc.WriteTLVBytes(0xAA, data))

	// Happy path: buffer is exactly the right size
	myBuf := make([]byte, 3)
	n, err := dec.ReadTLVBytesInto(0xAA, myBuf)
	require.NoError(t, err)
	assert.Equal(t, 3, n)
	assert.Equal(t, data, myBuf)

	// Error path: buffer is too small — must return ErrShortBuffer
	buf.Reset()
	require.NoError(t, enc.WriteTLVBytes(0xBB, data))

	shortBuf := make([]byte, 2)
	_, err = dec.ReadTLVBytesInto(0xBB, shortBuf)
	require.ErrorIs(t, err, ztlv.ErrShortBuffer)
}

func TestReadNested(t *testing.T) {
	t.Parallel()

	// Scenario: A "User" container (Tag 0xAA) contains:
	//   - Name  (Tag 0x01, String)
	//   - Age   (Tag 0x02, Uint8)
	//   - Address (Tag 0xBB, nested container) containing:
	//       - City (Tag 0x03, String)

	// 1. Build the inner Address container
	var userBuf bytes.Buffer
	enc := ztlv.NewEncoder(&userBuf)

	var addrBuf bytes.Buffer
	addrEnc := ztlv.NewEncoder(&addrBuf)
	require.NoError(t, addrEnc.WriteTLVString(0x03, "Paris"))

	// 2. Build the User container content
	require.NoError(t, enc.WriteTLVString(0x01, "Alice"))
	require.NoError(t, enc.WriteTLVUint8(0x02, 30))
	// Embed the Address container manually (Tag + Length + raw bytes)
	require.NoError(t, enc.WriteTag(0xBB))
	require.NoError(t, enc.WriteLength(uint32(addrBuf.Len())))
	_, err := userBuf.Write(addrBuf.Bytes())
	require.NoError(t, err)

	// 3. Wrap everything in the top-level User Tag
	var mainBuf bytes.Buffer
	mainEnc := ztlv.NewEncoder(&mainBuf)
	require.NoError(t, mainEnc.WriteTag(0xAA))
	require.NoError(t, mainEnc.WriteLength(uint32(userBuf.Len())))
	_, err = mainBuf.Write(userBuf.Bytes())
	require.NoError(t, err)

	// 4. Decode using ReadNested — the nested decoder is strictly limited to its container length
	dec := ztlv.NewDecoder(&mainBuf)

	err = dec.ReadNested(0xAA, func(d *ztlv.Decoder) error {
		name, err := d.ReadTLVString(0x01)
		require.NoError(t, err)
		assert.Equal(t, "Alice", name)

		age, err := d.ReadTLVUint8(0x02)
		require.NoError(t, err)
		assert.Equal(t, uint8(30), age)

		// Recurse into the nested Address container
		err = d.ReadNested(0xBB, func(d2 *ztlv.Decoder) error {
			city, err := d2.ReadTLVString(0x03)
			require.NoError(t, err)
			assert.Equal(t, "Paris", city)
			return nil
		})
		require.NoError(t, err)

		return nil
	})
	require.NoError(t, err)
}

func TestReadNested_PartialDrain(t *testing.T) {
	t.Parallel()

	// Scenario: a container holds two fields, but the callback only reads the first.
	// After ReadNested returns, the parent decoder must be correctly positioned
	// at the next top-level TLV (0xFF), not stuck inside unread container data.
	//
	// Stream layout:
	//   Container (0xAA)
	//     Field 1 (0x01) → we read this
	//     Field 2 (0x02) → we intentionally ignore this
	//   Next item (0xFF) → must be readable after the container

	var contentBuf bytes.Buffer
	enc := ztlv.NewEncoder(&contentBuf)
	require.NoError(t, enc.WriteTLVString(0x01, "read me"))
	require.NoError(t, enc.WriteTLVString(0x02, "ignore me"))

	var mainBuf bytes.Buffer
	mainEnc := ztlv.NewEncoder(&mainBuf)
	require.NoError(t, mainEnc.WriteTag(0xAA))
	require.NoError(t, mainEnc.WriteLength(uint32(contentBuf.Len())))
	_, err := mainBuf.Write(contentBuf.Bytes())
	require.NoError(t, err)

	// Write the sync-check item immediately after the container
	require.NoError(t, mainEnc.WriteTLVString(0xFF, "sync check"))

	dec := ztlv.NewDecoder(&mainBuf)

	err = dec.ReadNested(0xAA, func(d *ztlv.Decoder) error {
		val, err := d.ReadTLVString(0x01)
		require.NoError(t, err)
		assert.Equal(t, "read me", val)

		// Return early without reading Field 2.
		// ReadNested must automatically drain the remaining bytes (Field 2).
		return nil
	})
	require.NoError(t, err)

	// If draining failed we would read Field 2's tag/data instead of 0xFF here.
	val, err := dec.ReadTLVString(0xFF)
	require.NoError(t, err)
	assert.Equal(t, "sync check", val)
}

func TestBytes_Limits(t *testing.T) {
	t.Parallel()

	// Craft a malicious length prefix that exceeds DefaultMaxBytesSize.
	// The decoder must reject it immediately without allocating or reading the payload.
	var buf bytes.Buffer
	badLength := uint32(ztlv.DefaultMaxBytesSize + 1)
	require.NoError(t, binary.Write(&buf, binary.BigEndian, badLength))

	dec := ztlv.NewDecoder(&buf)
	_, err := dec.ReadBytes()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "payload exceeds configured limit")
}

func TestString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"Normal string", "hello world", "hello world"},
		{"Empty string", "", ""},
		{"Special characters", "Hako \x00 Vault 🚀", "Hako \x00 Vault 🚀"},
		{"Long String", string(make([]byte, 1000)), string(make([]byte, 1000))},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			enc := ztlv.NewEncoder(&buf)
			dec := ztlv.NewDecoder(&buf)

			require.NoError(t, enc.WriteString(tt.input))

			actual, err := dec.ReadString()
			require.NoError(t, err)
			assert.Equal(t, tt.expected, actual)
		})
	}
}

func TestString_Limits(t *testing.T) {
	t.Parallel()

	// Craft a malicious length prefix that exceeds DefaultMaxStringSize.
	// The decoder must reject it immediately — no allocation, no payload read.
	var buf bytes.Buffer
	badLength := uint32(ztlv.DefaultMaxStringSize + 1)
	require.NoError(t, binary.Write(&buf, binary.BigEndian, badLength))

	dec := ztlv.NewDecoder(&buf)
	_, err := dec.ReadString()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "payload exceeds configured limit")
}

func TestTime(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	enc := ztlv.NewEncoder(&buf)
	dec := ztlv.NewDecoder(&buf)

	// Use UTC to guarantee consistency across time zones.
	// No Truncate needed: the format stores full nanosecond precision.
	now := time.Now().UTC()

	require.NoError(t, enc.WriteTime(now))

	readTime, err := dec.ReadTime()
	require.NoError(t, err)

	// Verify both components independently for a clearer failure message
	assert.Equal(t, now.Unix(), readTime.Unix(), "Seconds mismatch")
	assert.Equal(t, now.Nanosecond(), readTime.Nanosecond(), "Nanoseconds mismatch")
	// Final sanity check via time.Equal (handles monotonic clock stripping)
	assert.True(t, now.Equal(readTime), "Time object mismatch: expected %v, got %v", now, readTime)

	// Test WriteTLVTime: tag + length prefix (12) + time payload
	buf.Reset()
	err = enc.WriteTLVTime(0x03, now)
	require.NoError(t, err)

	tag, err := dec.ReadTag()
	require.NoError(t, err)
	assert.Equal(t, ztlv.Tag(0x03), tag)

	// ReadTimePrefixed validates the length field before reading
	timeVal, err := dec.ReadTimePrefixed()
	require.NoError(t, err)
	assert.True(t, now.Equal(timeVal))

	// Test full symmetry: WriteTLVTime / ReadTLVTime
	buf.Reset()
	require.NoError(t, enc.WriteTLVTime(0x04, now))
	timeVal, err = dec.ReadTLVTime(0x04)
	require.NoError(t, err)
	assert.True(t, now.Equal(timeVal))
}

func TestReadTimePrefixed_Security(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	enc := ztlv.NewEncoder(&buf)
	dec := ztlv.NewDecoder(&buf)

	// A time value must always be exactly 12 bytes (8 sec + 4 nano).
	// Any other length must be rejected to prevent mis-parsing.

	// Case 1: Length too small (8 instead of 12)
	err := enc.WriteLength(8)
	require.NoError(t, err)

	_, err = dec.ReadTimePrefixed()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid time length")

	// Case 2: Length too large (100 instead of 12)
	buf.Reset()
	err = enc.WriteLength(100)
	require.NoError(t, err)

	_, err = dec.ReadTimePrefixed()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid time length")
}

func TestStrings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    []string
		expected []string
	}{
		{"Multiple strings", []string{"tag1", "tag2", "tag3"}, []string{"tag1", "tag2", "tag3"}},
		// An empty or nil slice encodes as count=0; decoding returns nil (not []string{}).
		// This is consistent with ReadStrings returning nil for the zero-count case.
		{"Empty slice", []string{}, nil},
		{"Nil slice", nil, nil},
		// Strings within the slice may themselves be empty — that is valid.
		{"Slice with empty strings", []string{"", "tag2", ""}, []string{"", "tag2", ""}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			enc := ztlv.NewEncoder(&buf)
			dec := ztlv.NewDecoder(&buf)

			require.NoError(t, enc.WriteStrings(tt.input))

			actual, err := dec.ReadStrings()
			require.NoError(t, err)

			assert.Equal(t, tt.expected, actual)
		})
	}
}

func TestStrings_Limits(t *testing.T) {
	t.Parallel()

	// Craft a malicious count that exceeds DefaultMaxListCount.
	// The decoder must reject it before allocating the slice or reading any element.
	var buf bytes.Buffer
	badCount := uint32(ztlv.DefaultMaxListCount + 1)
	require.NoError(t, binary.Write(&buf, binary.BigEndian, badCount))

	dec := ztlv.NewDecoder(&buf)
	_, err := dec.ReadStrings()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "list count exceeds configured limit")
}

func TestSkip(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	enc := ztlv.NewEncoder(&buf)
	dec := ztlv.NewDecoder(&buf)

	// Write three string fields back-to-back
	_ = enc.WriteString("chunk1")
	_ = enc.WriteString("chunk2_to_skip")
	_ = enc.WriteString("chunk3")

	// Read chunk 1 normally
	c1, err := dec.ReadString()
	require.NoError(t, err)
	assert.Equal(t, "chunk1", c1)

	// Read the length of chunk 2, then skip its payload without allocating
	len2, err := dec.ReadLength()
	require.NoError(t, err)
	err = dec.Skip(len2)
	require.NoError(t, err)

	// chunk 3 must be readable — stream is still in sync
	c3, err := dec.ReadString()
	require.NoError(t, err)
	assert.Equal(t, "chunk3", c3)
}

func TestSkip_EOF(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	dec := ztlv.NewDecoder(&buf)
	// 100 is within DefaultMaxSkipSize, so the limit check passes.
	// io.CopyN then hits EOF immediately on the empty buffer.
	err := dec.Skip(100)
	require.Error(t, err)
	assert.Equal(t, io.EOF, err)
}

func TestSkip_Limit(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	dec := ztlv.NewDecoder(&buf)
	// Exceeds MaxSkipSize — must fail before touching the reader,
	// preventing DoS via a huge length in an unknown tag.
	err := dec.Skip(ztlv.DefaultMaxSkipSize + 1)
	require.Error(t, err)
	assert.ErrorIs(t, err, ztlv.ErrPayloadTooLarge)
}

func TestTypedErrors(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	enc := ztlv.NewEncoder(&buf)
	dec := ztlv.NewDecoder(&buf)

	// Encode with tag 0x01, but attempt to decode expecting tag 0x02.
	// The decoder must return a typed UnexpectedTagError with both values populated.
	err := enc.WriteTLVString(0x01, "test")
	require.NoError(t, err)

	_, err = dec.ReadTLVString(0x02)
	require.Error(t, err)

	// Verify the error can be unwrapped to its concrete type
	var tagErr *ztlv.UnexpectedTagError
	require.ErrorAs(t, err, &tagErr)
	assert.Equal(t, ztlv.Tag(0x02), tagErr.Expected)
	assert.Equal(t, ztlv.Tag(0x01), tagErr.Actual)
	assert.Equal(t, "ztlv: expected tag 0x02, got 0x01", tagErr.Error())
}

func TestComplexTypes(t *testing.T) {
	t.Parallel()

	t.Run("Bool", func(t *testing.T) {
		var buf bytes.Buffer
		enc := ztlv.NewEncoder(&buf)
		dec := ztlv.NewDecoder(&buf)

		// Verify both true and false round-trip correctly (encoding is 0x01 / 0x00)
		require.NoError(t, enc.WriteTLVBool(0x10, true))
		require.NoError(t, enc.WriteTLVBool(0x11, false))

		v1, err := dec.ReadTLVBool(0x10)
		require.NoError(t, err)
		assert.True(t, v1)

		v2, err := dec.ReadTLVBool(0x11)
		require.NoError(t, err)
		assert.False(t, v2)
	})

	t.Run("Int64", func(t *testing.T) {
		var buf bytes.Buffer
		enc := ztlv.NewEncoder(&buf)
		dec := ztlv.NewDecoder(&buf)

		// Use a negative value to confirm two's-complement sign preservation
		val := int64(-1234567890)
		require.NoError(t, enc.WriteTLVInt64(0x20, val))

		readVal, err := dec.ReadTLVInt64(0x20)
		require.NoError(t, err)
		assert.Equal(t, val, readVal)
	})

	t.Run("Float64", func(t *testing.T) {
		var buf bytes.Buffer
		enc := ztlv.NewEncoder(&buf)
		dec := ztlv.NewDecoder(&buf)

		// Normal value
		val := 3.1415926535
		require.NoError(t, enc.WriteTLVFloat64(0x30, val))

		readVal, err := dec.ReadTLVFloat64(0x30)
		require.NoError(t, err)
		assert.Equal(t, val, readVal)

		// Special values: NaN must survive round-trip (bit pattern preserved via IEEE 754)
		buf.Reset()
		require.NoError(t, enc.WriteTLVFloat64(0x31, math.NaN()))
		readNaN, err := dec.ReadTLVFloat64(0x31)
		require.NoError(t, err)
		assert.True(t, math.IsNaN(readNaN))
	})
}

func TestValidation_InvalidLength(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	enc := ztlv.NewEncoder(&buf)
	dec := ztlv.NewDecoder(&buf)

	// Write an Int64 tag but with length=4 (half the expected 8 bytes).
	// ReadTLVInt64 must reject this with ErrInvalidLength.
	require.NoError(t, enc.WriteTag(0x40))
	require.NoError(t, enc.WriteLength(4))
	require.NoError(t, enc.WriteUint32(12345))

	_, err := dec.ReadTLVInt64(0x40)
	require.Error(t, err)
	assert.ErrorIs(t, err, ztlv.ErrInvalidLength)
}

func TestValidation_InvalidBool(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	enc := ztlv.NewEncoder(&buf)
	dec := ztlv.NewDecoder(&buf)

	// Write a bool tag with length=2 (expected length is exactly 1).
	// ReadTLVBool must reject this with ErrInvalidLength.
	require.NoError(t, enc.WriteTag(0x50))
	require.NoError(t, enc.WriteLength(2))
	require.NoError(t, enc.WriteUint16(0x0001))

	_, err := dec.ReadTLVBool(0x50)
	require.Error(t, err)
	assert.ErrorIs(t, err, ztlv.ErrInvalidLength)
}

// --- BENCHMARKS (Performance Proof) ---

func BenchmarkReadString(b *testing.B) {
	// Goal: prove ReadString produces exactly 1 alloc/op (the string buffer).
	// The unsafe.String trick avoids a second copy from []byte to string.
	var buf bytes.Buffer
	enc := ztlv.NewEncoder(&buf)
	payload := "Standard string for benchmark purposes"
	_ = enc.WriteString(payload)
	data := buf.Bytes()

	reader := bytes.NewReader(data)
	dec := ztlv.NewDecoder(reader)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		reader.Reset(data) // Rewind without allocation
		_, _ = dec.ReadString()
	}
}

func BenchmarkReadBytes(b *testing.B) {
	// Goal: prove ReadBytes produces exactly 1 alloc/op (the output slice).
	var buf bytes.Buffer
	enc := ztlv.NewEncoder(&buf)
	payload := make([]byte, 1024) // 1KB payload
	_ = enc.WriteBytes(payload)
	data := buf.Bytes()

	reader := bytes.NewReader(data)
	dec := ztlv.NewDecoder(reader)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		reader.Reset(data)
		_, _ = dec.ReadBytes()
	}
}

// --- FUZZING (Security Proof) ---
// Requires Go 1.18+. Run with: go test -fuzz=FuzzDecoder

func FuzzDecoder(f *testing.F) {
	// Seed corpus: known-valid inputs to give the fuzzer a starting point
	f.Add([]byte{0x00, 0x00, 0x00, 0x05, 'H', 'e', 'l', 'l', 'o'}) // Length-prefixed string
	f.Add([]byte{0x01})                                            // Just a tag byte

	f.Fuzz(func(t *testing.T, data []byte) {
		dec := ztlv.NewDecoder(bytes.NewReader(data))

		// Exercise all public decode paths with arbitrary input.
		// Success criterion: no panics, regardless of what garbage is fed in.
		_, _ = dec.ReadTag()
		_, _ = dec.ReadLength()
		_, _ = dec.ReadString()
		_, _ = dec.ReadBytes()
		_, _ = dec.ReadTime()
		_, _ = dec.ReadStrings()

		// Drive Skip with a value derived from the data itself
		if len(data) > 0 {
			_ = dec.Skip(uint32(data[0]))
		}
	})
}

func BenchmarkReadUint64(b *testing.B) {
	var buf bytes.Buffer
	enc := ztlv.NewEncoder(&buf)
	_ = enc.WriteUint64(12345678)
	data := buf.Bytes()
	reader := bytes.NewReader(data)
	dec := ztlv.NewDecoder(reader)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reader.Reset(data)
		_, _ = dec.ReadUint64()
	}
}
