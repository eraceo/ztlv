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

	// Test Tags
	require.NoError(t, enc.WriteTag(0x01))
	require.NoError(t, enc.WriteTag(0xFF))

	tag, err := dec.ReadTag()
	require.NoError(t, err)
	assert.Equal(t, ztlv.Tag(0x01), tag)

	tag, err = dec.ReadTag()
	require.NoError(t, err)
	assert.Equal(t, ztlv.Tag(0xFF), tag)

	// Test Lengths
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
		// Note: In the "Perfect" version, we prefer returning []byte{} (empty but non-nil)
		// instead of nil to prevent Null Pointer Exceptions.
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

	// Manually read Tag (none here) and Length
	length, err := dec.ReadLength()
	require.NoError(t, err)
	assert.Equal(t, uint32(4), length)

	// User provides buffer
	myBuf := make([]byte, 4)
	n, err := dec.ReadBytesInto(length, myBuf)
	require.NoError(t, err)
	assert.Equal(t, 4, n)
	assert.Equal(t, data, myBuf)

	// Test Error Case: Buffer too small
	// IMPORTANT: Since we pass length explicitly, the user is responsible for reading length first.
	// This avoids the "consumed length" bug.
	buf.Reset()
	require.NoError(t, enc.WriteBytes(data))
	length, err = dec.ReadLength()
	require.NoError(t, err)

	smallBuf := make([]byte, 2) // Too small
	_, err = dec.ReadBytesInto(length, smallBuf)
	require.ErrorIs(t, err, ztlv.ErrShortBuffer)

	// Since ReadBytesInto failed fast (without reading from reader), the data is still there!
	// We can retry with a bigger buffer!
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

	myBuf := make([]byte, 3)
	n, err := dec.ReadTLVBytesInto(0xAA, myBuf)
	require.NoError(t, err)
	assert.Equal(t, 3, n)
	assert.Equal(t, data, myBuf)

	// Test Short Buffer Error (Safe check)
	buf.Reset()
	require.NoError(t, enc.WriteTLVBytes(0xBB, data))

	shortBuf := make([]byte, 2)
	_, err = dec.ReadTLVBytesInto(0xBB, shortBuf)
	require.ErrorIs(t, err, ztlv.ErrShortBuffer)
}

func TestReadNested(t *testing.T) {
	t.Parallel()

	// Scenario: A "User" (Tag 0xAA) contains:
	//   - Name (Tag 0x01, String)
	//   - Age (Tag 0x02, Uint8)
	//   - Address (Tag 0xBB, Nested) containing:
	//       - City (Tag 0x03, String)

	// 1. Construct the nested payload manually
	var userBuf bytes.Buffer
	enc := ztlv.NewEncoder(&userBuf)

	// Address Content
	var addrBuf bytes.Buffer
	addrEnc := ztlv.NewEncoder(&addrBuf)
	require.NoError(t, addrEnc.WriteTLVString(0x03, "Paris"))

	// User Content
	// Name
	require.NoError(t, enc.WriteTLVString(0x01, "Alice"))
	// Age
	require.NoError(t, enc.WriteTLVUint8(0x02, 30))
	// Address (Nested) -> Write Tag, Length of addrBuf, then addrBuf content
	require.NoError(t, enc.WriteTag(0xBB))
	require.NoError(t, enc.WriteLength(uint32(addrBuf.Len())))
	_, err := userBuf.Write(addrBuf.Bytes())
	require.NoError(t, err)

	// Wrap everything in a main User Tag
	var mainBuf bytes.Buffer
	mainEnc := ztlv.NewEncoder(&mainBuf)
	require.NoError(t, mainEnc.WriteTag(0xAA))
	require.NoError(t, mainEnc.WriteLength(uint32(userBuf.Len())))
	_, err = mainBuf.Write(userBuf.Bytes())
	require.NoError(t, err)

	// 2. Decode using ReadNested
	dec := ztlv.NewDecoder(&mainBuf)

	err = dec.ReadNested(0xAA, func(d *ztlv.Decoder) error {
		// Read Name
		name, err := d.ReadTLVString(0x01)
		require.NoError(t, err)
		assert.Equal(t, "Alice", name)

		// Read Age
		age, err := d.ReadTLVUint8(0x02)
		require.NoError(t, err)
		assert.Equal(t, uint8(30), age)

		// Read Nested Address
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

	// Scenario:
	// Container (0xAA)
	//   - Field 1 (0x01) -> We will read this
	//   - Field 2 (0x02) -> We will IGNORE this
	// Next Item (0xFF) -> We must be able to read this successfully

	var contentBuf bytes.Buffer
	enc := ztlv.NewEncoder(&contentBuf)
	require.NoError(t, enc.WriteTLVString(0x01, "read me"))
	require.NoError(t, enc.WriteTLVString(0x02, "ignore me"))

	var mainBuf bytes.Buffer
	mainEnc := ztlv.NewEncoder(&mainBuf)
	// Write Container
	require.NoError(t, mainEnc.WriteTag(0xAA))
	require.NoError(t, mainEnc.WriteLength(uint32(contentBuf.Len())))
	_, err := mainBuf.Write(contentBuf.Bytes())
	require.NoError(t, err)

	// Write Next Item (to verify sync)
	require.NoError(t, mainEnc.WriteTLVString(0xFF, "sync check"))

	// Decode
	dec := ztlv.NewDecoder(&mainBuf)

	err = dec.ReadNested(0xAA, func(d *ztlv.Decoder) error {
		// Read Field 1
		val, err := d.ReadTLVString(0x01)
		require.NoError(t, err)
		assert.Equal(t, "read me", val)

		// DO NOT Read Field 2. Return early.
		// The decoder should automatically skip the rest of the container (Field 2).
		return nil
	})
	require.NoError(t, err)

	// Now try to read the next item (0xFF)
	// If draining failed, we would be reading garbage (Field 2's tag or data) instead of 0xFF
	val, err := dec.ReadTLVString(0xFF)
	require.NoError(t, err)
	assert.Equal(t, "sync check", val)
}

func TestBytes_Limits(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	// Craft a malicious payload indicating bytes larger than the default limit
	badLength := uint32(ztlv.DefaultMaxBytesSize + 1)
	require.NoError(t, binary.Write(&buf, binary.BigEndian, badLength))

	dec := ztlv.NewDecoder(&buf)
	_, err := dec.ReadBytes()
	require.Error(t, err)
	// Verify that the specific error or appropriate message is returned
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

	// IMPORTANT: Use UTC() to guarantee consistency across time zones.
	// We store sec+nano, so no Truncate is needed if the implementation is correct.
	now := time.Now().UTC()

	require.NoError(t, enc.WriteTime(now))

	readTime, err := dec.ReadTime()
	require.NoError(t, err)

	// Verify exact equality (Unix Seconds + Nanoseconds)
	assert.Equal(t, now.Unix(), readTime.Unix(), "Seconds mismatch")
	assert.Equal(t, now.Nanosecond(), readTime.Nanosecond(), "Nanoseconds mismatch")

	// Double check using .Equal()
	assert.True(t, now.Equal(readTime), "Time object mismatch: expected %v, got %v", now, readTime)

	// Test WriteTLVTime
	buf.Reset()
	err = enc.WriteTLVTime(0x03, now)
	require.NoError(t, err)

	tag, err := dec.ReadTag()
	require.NoError(t, err)
	assert.Equal(t, ztlv.Tag(0x03), tag)

	// Use ReadTimePrefixed for safety and correctness with TLV
	timeVal, err := dec.ReadTimePrefixed()
	require.NoError(t, err)
	assert.True(t, now.Equal(timeVal))

	// Test ReadTLVTime (Symmetry)
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

	// 1. Write a length that is NOT 12 (e.g., 8 bytes)
	err := enc.WriteLength(8)
	require.NoError(t, err)

	_, err = dec.ReadTimePrefixed()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid time length")

	// 2. Write a length that is too big
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
		{"Empty slice", []string{}, nil}, // nil is acceptable here for an empty list
		{"Nil slice", nil, nil},
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

	_ = enc.WriteString("chunk1")
	_ = enc.WriteString("chunk2_to_skip")
	_ = enc.WriteString("chunk3")

	// Read chunk 1
	c1, err := dec.ReadString()
	require.NoError(t, err)
	assert.Equal(t, "chunk1", c1)

	// Skip chunk 2
	len2, err := dec.ReadLength()
	require.NoError(t, err)
	err = dec.Skip(len2)
	require.NoError(t, err)

	// Read chunk 3
	c3, err := dec.ReadString()
	require.NoError(t, err)
	assert.Equal(t, "chunk3", c3)
}

func TestSkip_EOF(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	dec := ztlv.NewDecoder(&buf)
	err := dec.Skip(100)
	require.Error(t, err)
	assert.Equal(t, io.EOF, err)
}

func TestTypedErrors(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	enc := ztlv.NewEncoder(&buf)
	dec := ztlv.NewDecoder(&buf)

	// Write Tag 0x01
	err := enc.WriteTLVString(0x01, "test")
	require.NoError(t, err)

	// Expect Tag 0x02
	_, err = dec.ReadTLVString(0x02)
	require.Error(t, err)

	// Check typed error
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

		val := 3.1415926535
		require.NoError(t, enc.WriteTLVFloat64(0x30, val))

		readVal, err := dec.ReadTLVFloat64(0x30)
		require.NoError(t, err)
		assert.Equal(t, val, readVal)

		// Test NaN/Inf
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

	// Write an Int64 but with wrong length (e.g. 4 bytes instead of 8)
	require.NoError(t, enc.WriteTag(0x40))
	require.NoError(t, enc.WriteLength(4))
	require.NoError(t, enc.WriteUint32(12345))

	// Try to read as Int64 (expects 8 bytes)
	_, err := dec.ReadTLVInt64(0x40)
	require.Error(t, err)
	assert.ErrorIs(t, err, ztlv.ErrInvalidLength)
}

func TestValidation_InvalidBool(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	enc := ztlv.NewEncoder(&buf)
	dec := ztlv.NewDecoder(&buf)

	// Write a "bool" that is 2 bytes long
	require.NoError(t, enc.WriteTag(0x50))
	require.NoError(t, enc.WriteLength(2))
	require.NoError(t, enc.WriteUint16(0x0001))

	_, err := dec.ReadTLVBool(0x50)
	require.Error(t, err)
	assert.ErrorIs(t, err, ztlv.ErrInvalidLength)
}

// --- BENCHMARKS (Performance Proof) ---

func BenchmarkReadString(b *testing.B) {
	// Prepare a valid reading buffer
	var buf bytes.Buffer
	enc := ztlv.NewEncoder(&buf)
	payload := "Standard string for benchmark purposes"
	_ = enc.WriteString(payload)
	data := buf.Bytes()

	reader := bytes.NewReader(data)
	dec := ztlv.NewDecoder(reader)

	b.ReportAllocs() // Display allocs/op -> Should be 1 (the final string)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		reader.Reset(data) // Rewind without allocation
		_, _ = dec.ReadString()
	}
}

func BenchmarkReadBytes(b *testing.B) {
	var buf bytes.Buffer
	enc := ztlv.NewEncoder(&buf)
	payload := make([]byte, 1024) // 1KB
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
// Requires Go 1.18+

func FuzzDecoder(f *testing.F) {
	// Seed corpus: Valid cases to help the fuzzer start
	f.Add([]byte{0x00, 0x00, 0x00, 0x05, 'H', 'e', 'l', 'l', 'o'}) // Len + String
	f.Add([]byte{0x01})                                            // Just a tag

	f.Fuzz(func(t *testing.T, data []byte) {
		dec := ztlv.NewDecoder(bytes.NewReader(data))

		// Call methods in random order.
		// Goal: No panics, regardless of input data (random garbage).
		_, _ = dec.ReadTag()
		_, _ = dec.ReadLength()
		_, _ = dec.ReadString()
		_, _ = dec.ReadBytes()
		_, _ = dec.ReadTime()
		_, _ = dec.ReadStrings()

		// Also test Skip with an arbitrary value derived from data if possible
		if len(data) > 0 {
			_ = dec.Skip(uint32(data[0]))
		}
	})
}
