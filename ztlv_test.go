package ztlv_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/eraceo/ztlv/v2"
)

// --- TEST HELPERS (Stdlib only, zero dependencies) ---

func requireNoErr(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func requireErrIs(t *testing.T, err, target error) {
	t.Helper()
	if !errors.Is(err, target) {
		t.Fatalf("expected error matching %v, got %v", target, err)
	}
}

func assertEq[T comparable](t *testing.T, want, got T) {
	t.Helper()
	if want != got {
		t.Fatalf("mismatch: want %v, got %v", want, got)
	}
}

func assertSliceEq[T comparable](t *testing.T, want, got []T) {
	t.Helper()
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("slice mismatch: want %#v, got %#v", want, got)
	}
}

type nonSeekerReader struct {
	r io.Reader
}

func (ns nonSeekerReader) Read(p []byte) (int, error) {
	return ns.r.Read(p)
}

type failingSeekerReader struct {
	r io.Reader
}

func (fs failingSeekerReader) Read(p []byte) (int, error) {
	return fs.r.Read(p)
}

func (fs failingSeekerReader) Seek(int64, int) (int64, error) {
	return 0, errors.New("ESPIPE: illegal seek")
}

type failAfterNWriter struct {
	limit   int
	written int
}

var errSimulatedWrite = errors.New("simulated write failure")

func (w *failAfterNWriter) Write(p []byte) (int, error) {
	if w.written >= w.limit {
		return 0, errSimulatedWrite
	}
	avail := w.limit - w.written
	if len(p) > avail {
		w.written += avail
		return avail, errSimulatedWrite
	}
	w.written += len(p)
	return len(p), nil
}

// --- UNIT & FUNCTIONAL TESTS ---

func TestTagAndLength(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	enc := ztlv.NewEncoder(&buf)
	dec := ztlv.NewDecoder(&buf)

	requireNoErr(t, enc.WriteTag(0x01))
	requireNoErr(t, enc.WriteTag(0xFF))

	tag, err := dec.ReadTag()
	requireNoErr(t, err)
	assertEq(t, ztlv.Tag(0x01), tag)

	tag, err = dec.ReadTag()
	requireNoErr(t, err)
	assertEq(t, ztlv.Tag(0xFF), tag)

	buf.Reset()
	requireNoErr(t, enc.WriteLength(0))
	requireNoErr(t, enc.WriteLength(42))
	requireNoErr(t, enc.WriteLength(math.MaxUint32))

	length, err := dec.ReadLength()
	requireNoErr(t, err)
	assertEq(t, uint32(0), length)

	length, err = dec.ReadLength()
	requireNoErr(t, err)
	assertEq(t, uint32(42), length)

	length, err = dec.ReadLength()
	requireNoErr(t, err)
	assertEq(t, uint32(math.MaxUint32), length)
}

func TestReset(t *testing.T) {
	t.Parallel()

	var buf1, buf2 bytes.Buffer
	enc := ztlv.NewEncoder(&buf1)
	requireNoErr(t, enc.WriteTLVUint64(0x01, 111))

	// Reuse Encoder on a second buffer while preserving safety limits on Decoder.
	enc.Reset(&buf2)
	requireNoErr(t, enc.WriteTLVString(0x02, "second"))

	dec := ztlv.NewDecoder(&buf1)
	dec.MaxStringSize = 16

	v1, err := dec.ReadTLVUint64(0x01)
	requireNoErr(t, err)
	assertEq(t, uint64(111), v1)

	dec.Reset(&buf2)
	assertEq(t, uint32(16), dec.MaxStringSize)
	v2, err := dec.ReadTLVString(0x02)
	requireNoErr(t, err)
	assertEq(t, "second", v2)
}

func TestAllPrimitiveTypes(t *testing.T) {
	t.Parallel()

	t.Run("Bool", func(t *testing.T) {
		var buf bytes.Buffer
		enc := ztlv.NewEncoder(&buf)
		dec := ztlv.NewDecoder(&buf)

		requireNoErr(t, enc.WriteBool(true))
		requireNoErr(t, enc.WriteBool(false))
		requireNoErr(t, enc.WriteTLVBool(0x10, true))
		requireNoErr(t, enc.WriteTLVBool(0x11, false))
		requireNoErr(t, enc.WriteTLVBool(0x12, true))

		b1, err := dec.ReadBool()
		requireNoErr(t, err)
		assertEq(t, true, b1)

		b2, err := dec.ReadBool()
		requireNoErr(t, err)
		assertEq(t, false, b2)

		b3, err := dec.ReadTLVBool(0x10)
		requireNoErr(t, err)
		assertEq(t, true, b3)

		b4, err := dec.ReadTLVBool(0x11)
		requireNoErr(t, err)
		assertEq(t, false, b4)

		tag, err := dec.ReadTag()
		requireNoErr(t, err)
		assertEq(t, ztlv.Tag(0x12), tag)
		b5, err := dec.ReadBoolPrefixed()
		requireNoErr(t, err)
		assertEq(t, true, b5)
	})

	t.Run("UnsignedIntegers", func(t *testing.T) {
		var buf bytes.Buffer
		enc := ztlv.NewEncoder(&buf)
		dec := ztlv.NewDecoder(&buf)

		requireNoErr(t, enc.WriteUint8(0xAB))
		requireNoErr(t, enc.WriteUint16(0xCAFE))
		requireNoErr(t, enc.WriteUint32(0xDEADBEEF))
		requireNoErr(t, enc.WriteUint64(0x0102030405060708))

		u8, err := dec.ReadUint8()
		requireNoErr(t, err)
		assertEq(t, uint8(0xAB), u8)

		u16, err := dec.ReadUint16()
		requireNoErr(t, err)
		assertEq(t, uint16(0xCAFE), u16)

		u32, err := dec.ReadUint32()
		requireNoErr(t, err)
		assertEq(t, uint32(0xDEADBEEF), u32)

		u64, err := dec.ReadUint64()
		requireNoErr(t, err)
		assertEq(t, uint64(0x0102030405060708), u64)

		buf.Reset()
		requireNoErr(t, enc.WriteTLVUint8(0x01, 255))
		requireNoErr(t, enc.WriteTLVUint16(0x02, 65535))
		requireNoErr(t, enc.WriteTLVUint32(0x03, 4000000000))
		requireNoErr(t, enc.WriteTLVUint64(0x04, math.MaxUint64))

		tu8, err := dec.ReadTLVUint8(0x01)
		requireNoErr(t, err)
		assertEq(t, uint8(255), tu8)

		tu16, err := dec.ReadTLVUint16(0x02)
		requireNoErr(t, err)
		assertEq(t, uint16(65535), tu16)

		tu32, err := dec.ReadTLVUint32(0x03)
		requireNoErr(t, err)
		assertEq(t, uint32(4000000000), tu32)

		tu64, err := dec.ReadTLVUint64(0x04)
		requireNoErr(t, err)
		assertEq(t, uint64(math.MaxUint64), tu64)
	})

	t.Run("SignedIntegers", func(t *testing.T) {
		var buf bytes.Buffer
		enc := ztlv.NewEncoder(&buf)
		dec := ztlv.NewDecoder(&buf)

		requireNoErr(t, enc.WriteInt8(-42))
		requireNoErr(t, enc.WriteInt16(-12345))
		requireNoErr(t, enc.WriteInt32(-1234567890))
		requireNoErr(t, enc.WriteInt64(-9223372036854775808))

		i8, err := dec.ReadInt8()
		requireNoErr(t, err)
		assertEq(t, int8(-42), i8)

		i16, err := dec.ReadInt16()
		requireNoErr(t, err)
		assertEq(t, int16(-12345), i16)

		i32, err := dec.ReadInt32()
		requireNoErr(t, err)
		assertEq(t, int32(-1234567890), i32)

		i64, err := dec.ReadInt64()
		requireNoErr(t, err)
		assertEq(t, int64(-9223372036854775808), i64)

		buf.Reset()
		requireNoErr(t, enc.WriteTLVInt8(0x11, math.MinInt8))
		requireNoErr(t, enc.WriteTLVInt16(0x12, math.MinInt16))
		requireNoErr(t, enc.WriteTLVInt32(0x13, math.MinInt32))
		requireNoErr(t, enc.WriteTLVInt64(0x14, math.MinInt64))

		ti8, err := dec.ReadTLVInt8(0x11)
		requireNoErr(t, err)
		assertEq(t, int8(math.MinInt8), ti8)

		ti16, err := dec.ReadTLVInt16(0x12)
		requireNoErr(t, err)
		assertEq(t, int16(math.MinInt16), ti16)

		ti32, err := dec.ReadTLVInt32(0x13)
		requireNoErr(t, err)
		assertEq(t, int32(math.MinInt32), ti32)

		ti64, err := dec.ReadTLVInt64(0x14)
		requireNoErr(t, err)
		assertEq(t, int64(math.MinInt64), ti64)
	})

	t.Run("Floats", func(t *testing.T) {
		var buf bytes.Buffer
		enc := ztlv.NewEncoder(&buf)
		dec := ztlv.NewDecoder(&buf)

		requireNoErr(t, enc.WriteFloat32(-12.5))
		requireNoErr(t, enc.WriteFloat64(3.141592653589793))
		requireNoErr(t, enc.WriteTLVFloat32(0x30, float32(math.Inf(-1))))
		requireNoErr(t, enc.WriteTLVFloat64(0x31, math.NaN()))

		f32, err := dec.ReadFloat32()
		requireNoErr(t, err)
		assertEq(t, float32(-12.5), f32)

		f64, err := dec.ReadFloat64()
		requireNoErr(t, err)
		assertEq(t, 3.141592653589793, f64)

		tf32, err := dec.ReadTLVFloat32(0x30)
		requireNoErr(t, err)
		if !math.IsInf(float64(tf32), -1) {
			t.Fatalf("expected -Inf, got %v", tf32)
		}

		tf64, err := dec.ReadTLVFloat64(0x31)
		requireNoErr(t, err)
		if !math.IsNaN(tf64) {
			t.Fatalf("expected NaN, got %v", tf64)
		}
	})
}

func TestSwitchLoopWithPrefixedDecoders(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	enc := ztlv.NewEncoder(&buf)

	requireNoErr(t, enc.WriteTLVBool(0x01, true))
	requireNoErr(t, enc.WriteTLVUint8(0x02, 7))
	requireNoErr(t, enc.WriteTLVUint16(0x03, 500))
	requireNoErr(t, enc.WriteTLVUint32(0x04, 70000))
	requireNoErr(t, enc.WriteTLVUint64(0x05, 9000000000))
	requireNoErr(t, enc.WriteTLVInt8(0x06, -8))
	requireNoErr(t, enc.WriteTLVInt16(0x07, -500))
	requireNoErr(t, enc.WriteTLVInt32(0x08, -70000))
	requireNoErr(t, enc.WriteTLVInt64(0x09, -9000000000))
	requireNoErr(t, enc.WriteTLVFloat32(0x0A, 1.5))
	requireNoErr(t, enc.WriteTLVFloat64(0x0B, 2.5))
	requireNoErr(t, enc.WriteTLVString(0x0C, "hello"))
	requireNoErr(t, enc.WriteTLVStrings(0x0D, []string{"a", "b"}))
	requireNoErr(t, enc.WriteTLVBytes(0x0E, []byte{1, 2}))
	requireNoErr(t, enc.WriteTLVTime(0x0F, time.Unix(1700000000, 123).UTC()))
	requireNoErr(t, enc.WriteNested(0x10, func(e *ztlv.Encoder) error {
		return e.WriteTLVString(0x01, "inside")
	}))
	requireNoErr(t, enc.WriteTLVStrings(0xFE, []string{"skip", "me", "safely"}))
	requireNoErr(t, enc.WriteTLVUint8(0xFF, 99))

	dec := ztlv.NewDecoder(&buf)
	var seenMask uint32
	var innerStr string
	var tail uint8

	for {
		tag, err := dec.ReadTag()
		if errors.Is(err, io.EOF) {
			break
		}
		requireNoErr(t, err)

		switch tag {
		case 0x01:
			v, e := dec.ReadBoolPrefixed()
			requireNoErr(t, e)
			assertEq(t, true, v)
		case 0x02:
			v, e := dec.ReadUint8Prefixed()
			requireNoErr(t, e)
			assertEq(t, uint8(7), v)
		case 0x03:
			v, e := dec.ReadUint16Prefixed()
			requireNoErr(t, e)
			assertEq(t, uint16(500), v)
		case 0x04:
			v, e := dec.ReadUint32Prefixed()
			requireNoErr(t, e)
			assertEq(t, uint32(70000), v)
		case 0x05:
			v, e := dec.ReadUint64Prefixed()
			requireNoErr(t, e)
			assertEq(t, uint64(9000000000), v)
		case 0x06:
			v, e := dec.ReadInt8Prefixed()
			requireNoErr(t, e)
			assertEq(t, int8(-8), v)
		case 0x07:
			v, e := dec.ReadInt16Prefixed()
			requireNoErr(t, e)
			assertEq(t, int16(-500), v)
		case 0x08:
			v, e := dec.ReadInt32Prefixed()
			requireNoErr(t, e)
			assertEq(t, int32(-70000), v)
		case 0x09:
			v, e := dec.ReadInt64Prefixed()
			requireNoErr(t, e)
			assertEq(t, int64(-9000000000), v)
		case 0x0A:
			v, e := dec.ReadFloat32Prefixed()
			requireNoErr(t, e)
			assertEq(t, float32(1.5), v)
		case 0x0B:
			v, e := dec.ReadFloat64Prefixed()
			requireNoErr(t, e)
			assertEq(t, 2.5, v)
		case 0x0C:
			v, e := dec.ReadString()
			requireNoErr(t, e)
			assertEq(t, "hello", v)
		case 0x0D:
			v, e := dec.ReadStringsPrefixed()
			requireNoErr(t, e)
			assertSliceEq(t, []string{"a", "b"}, v)
		case 0x0E:
			v, e := dec.ReadBytes()
			requireNoErr(t, e)
			assertSliceEq(t, []byte{1, 2}, v)
		case 0x0F:
			v, e := dec.ReadTimePrefixed()
			requireNoErr(t, e)
			assertEq(t, int64(1700000000), v.Unix())
		case 0x10:
			e := dec.ReadNestedBody(func(d *ztlv.Decoder) error {
				var errInner error
				innerStr, errInner = d.ReadTLVString(0x01)
				return errInner
			})
			requireNoErr(t, e)
		case 0xFF:
			var e error
			tail, e = dec.ReadUint8Prefixed()
			requireNoErr(t, e)
		default:
			// Unknown tag 0xFE (WriteTLVStrings) must be skipped cleanly without desyncing 0xFF.
			requireNoErr(t, dec.SkipTLV())
		}
		if tag <= 0x10 {
			seenMask |= 1 << tag
		}
	}

	assertEq(t, uint32(0x1FFFE), seenMask)
	assertEq(t, "inside", innerStr)
	assertEq(t, uint8(99), tail)
}

func TestBytes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    []byte
		expected []byte
	}{
		{"Normal bytes", []byte{0xDE, 0xAD, 0xBE, 0xEF}, []byte{0xDE, 0xAD, 0xBE, 0xEF}},
		{"Empty bytes", []byte{}, []byte{}},
		{"Nil bytes", nil, []byte{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			enc := ztlv.NewEncoder(&buf)
			dec := ztlv.NewDecoder(&buf)

			requireNoErr(t, enc.WriteBytes(tt.input))
			actual, err := dec.ReadBytes()
			requireNoErr(t, err)
			assertSliceEq(t, tt.expected, actual)

			buf.Reset()
			requireNoErr(t, enc.WriteTLVBytes(0x42, tt.input))
			actualTLV, err := dec.ReadTLVBytes(0x42)
			requireNoErr(t, err)
			assertSliceEq(t, tt.expected, actualTLV)
		})
	}
}

func TestReadBytesInto_And_ShortBufferRecovery(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	enc := ztlv.NewEncoder(&buf)
	dec := ztlv.NewDecoder(&buf)

	data := []byte{0xCA, 0xFE, 0xBA, 0xBE}
	requireNoErr(t, enc.WriteBytes(data))

	length, err := dec.ReadLength()
	requireNoErr(t, err)
	assertEq(t, uint32(4), length)

	myBuf := make([]byte, 4)
	n, err := dec.ReadBytesInto(length, myBuf)
	requireNoErr(t, err)
	assertEq(t, 4, n)
	assertSliceEq(t, data, myBuf)

	// ReadBytesInto preserves stream state on ErrShortBuffer and allows retry.
	buf.Reset()
	requireNoErr(t, enc.WriteBytes(data))
	length, err = dec.ReadLength()
	requireNoErr(t, err)

	_, err = dec.ReadBytesInto(length, make([]byte, 2))
	requireErrIs(t, err, ztlv.ErrShortBuffer)

	bigBuf := make([]byte, 4)
	n, err = dec.ReadBytesInto(length, bigBuf)
	requireNoErr(t, err)
	assertEq(t, 4, n)
	assertSliceEq(t, data, bigBuf)

	// ReadTLVBytesInto happy path + ShortBufferError recovery.
	buf.Reset()
	requireNoErr(t, enc.WriteTLVBytes(0xAA, []byte{1, 2, 3}))
	requireNoErr(t, enc.WriteTLVBytes(0xBB, []byte{9, 8}))
	requireNoErr(t, enc.WriteTLVBytes(0xCC, nil))

	n, err = dec.ReadTLVBytesInto(0xAA, make([]byte, 3))
	requireNoErr(t, err)
	assertEq(t, 3, n)

	_, err = dec.ReadTLVBytesInto(0xBB, make([]byte, 1))
	requireErrIs(t, err, ztlv.ErrShortBuffer)
	var sbErr *ztlv.ShortBufferError
	if !errors.As(err, &sbErr) {
		t.Fatalf("expected *ShortBufferError, got %T", err)
	}
	assertEq(t, uint32(2), sbErr.Required)
	assertEq(t, 1, sbErr.Available)

	// Recover without losing stream sync!
	recovered := make([]byte, sbErr.Required)
	n, err = dec.ReadBytesInto(sbErr.Required, recovered)
	requireNoErr(t, err)
	assertEq(t, 2, n)
	assertSliceEq(t, []byte{9, 8}, recovered)

	// Zero-length ReadTLVBytesInto works even with nil buffer.
	n, err = dec.ReadTLVBytesInto(0xCC, nil)
	requireNoErr(t, err)
	assertEq(t, 0, n)

	// Partial read returns actual byte count copied before EOF, not requested length.
	buf.Reset()
	requireNoErr(t, enc.WriteLength(10))
	_, _ = buf.Write([]byte{1, 2, 3})
	length, err = dec.ReadLength()
	requireNoErr(t, err)
	partial := make([]byte, 10)
	n, err = dec.ReadBytesInto(length, partial)
	requireErrIs(t, err, io.ErrUnexpectedEOF)
	assertEq(t, 3, n)

	// Enforce MaxBytesSize in ReadBytesInto.
	dec.MaxBytesSize = 4
	_, err = dec.ReadBytesInto(5, make([]byte, 10))
	requireErrIs(t, err, ztlv.ErrPayloadTooLarge)
}

func TestNestedWriteAndRead(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	enc := ztlv.NewEncoder(&buf)

	err := enc.WriteNested(0xAA, func(u *ztlv.Encoder) error {
		if err := u.WriteTLVString(0x01, "Alice"); err != nil {
			return err
		}
		if err := u.WriteTLVUint8(0x02, 30); err != nil {
			return err
		}
		return u.WriteNested(0xBB, func(a *ztlv.Encoder) error {
			return a.WriteTLVString(0x03, "Paris")
		})
	})
	requireNoErr(t, err)

	// Also verify oversized nested buffer (> 64KB) works and doesn't break subsequent writes.
	bigPayload := bytes.Repeat([]byte{'x'}, 70<<10)
	requireNoErr(t, enc.WriteNested(0xCC, func(e *ztlv.Encoder) error {
		return e.WriteTLVBytes(0x01, bigPayload)
	}))
	requireNoErr(t, enc.WriteTLVString(0xDD, "after-big"))

	dec := ztlv.NewDecoder(&buf)
	err = dec.ReadNested(0xAA, func(d *ztlv.Decoder) error {
		name, err := d.ReadTLVString(0x01)
		requireNoErr(t, err)
		assertEq(t, "Alice", name)

		age, err := d.ReadTLVUint8(0x02)
		requireNoErr(t, err)
		assertEq(t, uint8(30), age)

		return d.ReadNested(0xBB, func(d2 *ztlv.Decoder) error {
			city, err := d2.ReadTLVString(0x03)
			requireNoErr(t, err)
			assertEq(t, "Paris", city)
			return nil
		})
	})
	requireNoErr(t, err)

	err = dec.ReadNested(0xCC, func(d *ztlv.Decoder) error {
		got, err := d.ReadTLVBytes(0x01)
		requireNoErr(t, err)
		assertEq(t, len(bigPayload), len(got))
		return nil
	})
	requireNoErr(t, err)

	after, err := dec.ReadTLVString(0xDD)
	requireNoErr(t, err)
	assertEq(t, "after-big", after)
}

func TestReadNested_PartialDrainAndErrors(t *testing.T) {
	t.Parallel()

	// 1. Partial drain on non-seeker stream leaves parent synced at next tag.
	var buf bytes.Buffer
	enc := ztlv.NewEncoder(&buf)
	requireNoErr(t, enc.WriteNested(0xAA, func(e *ztlv.Encoder) error {
		if err := e.WriteTLVString(0x01, "read me"); err != nil {
			return err
		}
		return e.WriteTLVString(0x02, "ignore me")
	}))
	requireNoErr(t, enc.WriteTLVString(0xFF, "sync check"))

	dec := ztlv.NewDecoder(nonSeekerReader{r: &buf})
	err := dec.ReadNested(0xAA, func(d *ztlv.Decoder) error {
		val, err := d.ReadTLVString(0x01)
		requireNoErr(t, err)
		assertEq(t, "read me", val)
		return nil
	})
	requireNoErr(t, err)

	val, err := dec.ReadTLVString(0xFF)
	requireNoErr(t, err)
	assertEq(t, "sync check", val)

	// 2. MaxSkipSize blocks huge unread drain in ReadNested (DoS protection).
	buf.Reset()
	requireNoErr(t, enc.WriteTag(0xAA))
	requireNoErr(t, enc.WriteLength(1024))
	_, _ = buf.Write(make([]byte, 1024))

	dec = ztlv.NewDecoder(&buf)
	dec.MaxSkipSize = 64
	err = dec.ReadNested(0xAA, func(d *ztlv.Decoder) error {
		return nil
	})
	requireErrIs(t, err, ztlv.ErrPayloadTooLarge)

	// 3. Truncated nested body returns io.ErrUnexpectedEOF (even on seekable bytes.Reader).
	buf.Reset()
	requireNoErr(t, enc.WriteTag(0xAA))
	requireNoErr(t, enc.WriteLength(50))
	_, _ = buf.Write([]byte("short"))

	dec = ztlv.NewDecoder(bytes.NewReader(buf.Bytes()))
	err = dec.ReadNested(0xAA, func(d *ztlv.Decoder) error {
		return nil
	})
	requireErrIs(t, err, io.ErrUnexpectedEOF)

	// 4. Callback error propagates directly.
	buf.Reset()
	requireNoErr(t, enc.WriteNested(0xAA, func(e *ztlv.Encoder) error {
		return e.WriteTLVUint8(0x01, 1)
	}))
	sentinel := errors.New("boom")
	dec = ztlv.NewDecoder(&buf)
	err = dec.ReadNested(0xAA, func(*ztlv.Decoder) error {
		return sentinel
	})
	requireErrIs(t, err, sentinel)
}

func TestTimeAndValidation(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	enc := ztlv.NewEncoder(&buf)
	dec := ztlv.NewDecoder(&buf)

	times := []time.Time{
		time.Now().UTC(),
		time.Unix(-1000000, 123456789).UTC(), // Pre-1970 negative timestamp
		time.Date(2300, 1, 2, 3, 4, 5, 999999999, time.UTC),
		{},
	}

	for _, ts := range times {
		buf.Reset()
		requireNoErr(t, enc.WriteTime(ts))
		got, err := dec.ReadTime()
		requireNoErr(t, err)
		if !ts.Equal(got) {
			t.Fatalf("time mismatch: want %v, got %v", ts, got)
		}

		buf.Reset()
		requireNoErr(t, enc.WriteTLVTime(0x04, ts))
		gotTLV, err := dec.ReadTLVTime(0x04)
		requireNoErr(t, err)
		if !ts.Equal(gotTLV) {
			t.Fatalf("TLV time mismatch: want %v, got %v", ts, gotTLV)
		}
	}

	// Out-of-range nanoseconds (>= 1e9) must return ErrInvalidTime.
	buf.Reset()
	requireNoErr(t, enc.WriteInt64(1700000000))
	requireNoErr(t, enc.WriteUint32(1_000_000_000))
	_, err := dec.ReadTime()
	requireErrIs(t, err, ztlv.ErrInvalidTime)

	// Invalid prefixed time length must return ErrInvalidLength.
	buf.Reset()
	requireNoErr(t, enc.WriteLength(8))
	_, err = dec.ReadTimePrefixed()
	requireErrIs(t, err, ztlv.ErrInvalidLength)
}

func TestStringAndStrings(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	enc := ztlv.NewEncoder(&buf)
	dec := ztlv.NewDecoder(&buf)

	for _, s := range []string{"", "hello", "Hako \x00 Vault 🚀", strings.Repeat("a", 1000)} {
		buf.Reset()
		requireNoErr(t, enc.WriteString(s))
		got, err := dec.ReadString()
		requireNoErr(t, err)
		assertEq(t, s, got)
	}

	// String lists: raw and TLV-framed.
	lists := [][]string{
		{"tag1", "tag2", "tag3"},
		{},
		nil,
		{"", "mid", ""},
	}
	for _, list := range lists {
		buf.Reset()
		requireNoErr(t, enc.WriteStrings(list))
		got, err := dec.ReadStrings()
		requireNoErr(t, err)
		var want []string
		if len(list) > 0 {
			want = list
		}
		assertSliceEq(t, want, got)

		buf.Reset()
		requireNoErr(t, enc.WriteTLVStrings(0x55, list))
		gotTLV, err := dec.ReadTLVStrings(0x55)
		requireNoErr(t, err)
		assertSliceEq(t, want, gotTLV)
	}

	// Large list (> maxListPrealloc=256) exercises growth path.
	many := make([]string, 300)
	for i := range many {
		many[i] = "x"
	}
	buf.Reset()
	requireNoErr(t, enc.WriteTLVStrings(0x56, many))
	gotMany, err := dec.ReadTLVStrings(0x56)
	requireNoErr(t, err)
	assertSliceEq(t, many, gotMany)
}

func TestLimitsAndFramingErrors(t *testing.T) {
	t.Parallel()

	t.Run("MaxBytesSize", func(t *testing.T) {
		var buf bytes.Buffer
		_ = binary.Write(&buf, binary.BigEndian, uint32(ztlv.DefaultMaxBytesSize+1))
		dec := ztlv.NewDecoder(&buf)
		_, err := dec.ReadBytes()
		requireErrIs(t, err, ztlv.ErrPayloadTooLarge)
	})

	t.Run("MaxStringSize", func(t *testing.T) {
		var buf bytes.Buffer
		_ = binary.Write(&buf, binary.BigEndian, uint32(ztlv.DefaultMaxStringSize+1))
		dec := ztlv.NewDecoder(&buf)
		_, err := dec.ReadString()
		requireErrIs(t, err, ztlv.ErrPayloadTooLarge)
	})

	t.Run("MaxListCount", func(t *testing.T) {
		var buf bytes.Buffer
		_ = binary.Write(&buf, binary.BigEndian, uint32(ztlv.DefaultMaxListCount+1))
		dec := ztlv.NewDecoder(&buf)
		_, err := dec.ReadStrings()
		requireErrIs(t, err, ztlv.ErrListTooLarge)
	})

	t.Run("TLVStringsValidation", func(t *testing.T) {
		// payloadLen < 4
		var buf bytes.Buffer
		enc := ztlv.NewEncoder(&buf)
		requireNoErr(t, enc.WriteTag(0x10))
		requireNoErr(t, enc.WriteLength(2))
		dec := ztlv.NewDecoder(&buf)
		_, err := dec.ReadTLVStrings(0x10)
		requireErrIs(t, err, ztlv.ErrInvalidLength)

		// Impossible count in payloadLen (count=10 inside 8 bytes)
		buf.Reset()
		requireNoErr(t, enc.WriteTag(0x10))
		requireNoErr(t, enc.WriteLength(8))
		requireNoErr(t, enc.WriteLength(10))
		requireNoErr(t, enc.WriteLength(0))
		dec = ztlv.NewDecoder(&buf)
		_, err = dec.ReadTLVStrings(0x10)
		requireErrIs(t, err, ztlv.ErrInvalidLength)

		// Trailing bytes inside TLV string list frame
		buf.Reset()
		requireNoErr(t, enc.WriteTag(0x10))
		requireNoErr(t, enc.WriteLength(8)) // 4 bytes count=0 + 4 trailing garbage bytes
		requireNoErr(t, enc.WriteLength(0))
		requireNoErr(t, enc.WriteLength(0))
		dec = ztlv.NewDecoder(&buf)
		_, err = dec.ReadTLVStrings(0x10)
		requireErrIs(t, err, ztlv.ErrInvalidLength)

		// High limits (MaxUint32) must not wrap uint64 multiplication.
		buf.Reset()
		requireNoErr(t, enc.WriteTLVStrings(0x10, []string{"ok"}))
		dec = ztlv.NewDecoder(&buf)
		dec.MaxListCount = math.MaxUint32
		dec.MaxStringSize = math.MaxUint32
		got, err := dec.ReadTLVStrings(0x10)
		requireNoErr(t, err)
		assertSliceEq(t, []string{"ok"}, got)
	})

	t.Run("UnexpectedTagError", func(t *testing.T) {
		var buf bytes.Buffer
		enc := ztlv.NewEncoder(&buf)
		requireNoErr(t, enc.WriteTLVString(0x01, "test"))
		dec := ztlv.NewDecoder(&buf)

		_, err := dec.ReadTLVString(0x02)
		requireErrIs(t, err, ztlv.ErrInvalidTag)

		var tagErr *ztlv.UnexpectedTagError
		if !errors.As(err, &tagErr) {
			t.Fatalf("expected *UnexpectedTagError, got %T", err)
		}
		assertEq(t, ztlv.Tag(0x02), tagErr.Expected)
		assertEq(t, ztlv.Tag(0x01), tagErr.Actual)
		assertEq(t, "ztlv: expected tag 0x02, got 0x01", tagErr.Error())
	})

	t.Run("InvalidFixedLengths", func(t *testing.T) {
		badLengthTests := []struct {
			name string
			fn   func(*ztlv.Decoder) error
		}{
			{"Bool", func(d *ztlv.Decoder) error { _, err := d.ReadTLVBool(0x01); return err }},
			{"Uint8", func(d *ztlv.Decoder) error { _, err := d.ReadTLVUint8(0x01); return err }},
			{"Uint16", func(d *ztlv.Decoder) error { _, err := d.ReadTLVUint16(0x01); return err }},
			{"Uint32", func(d *ztlv.Decoder) error { _, err := d.ReadTLVUint32(0x01); return err }},
			{"Uint64", func(d *ztlv.Decoder) error { _, err := d.ReadTLVUint64(0x01); return err }},
			{"Int8", func(d *ztlv.Decoder) error { _, err := d.ReadTLVInt8(0x01); return err }},
			{"Int16", func(d *ztlv.Decoder) error { _, err := d.ReadTLVInt16(0x01); return err }},
			{"Int32", func(d *ztlv.Decoder) error { _, err := d.ReadTLVInt32(0x01); return err }},
			{"Int64", func(d *ztlv.Decoder) error { _, err := d.ReadTLVInt64(0x01); return err }},
			{"Float32", func(d *ztlv.Decoder) error { _, err := d.ReadTLVFloat32(0x01); return err }},
			{"Float64", func(d *ztlv.Decoder) error { _, err := d.ReadTLVFloat64(0x01); return err }},
			{"Time", func(d *ztlv.Decoder) error { _, err := d.ReadTLVTime(0x01); return err }},
		}

		for _, tc := range badLengthTests {
			var buf bytes.Buffer
			enc := ztlv.NewEncoder(&buf)
			requireNoErr(t, enc.WriteTag(0x01))
			requireNoErr(t, enc.WriteLength(99)) // Wrong length for every fixed type
			dec := ztlv.NewDecoder(&buf)
			err := tc.fn(dec)
			requireErrIs(t, err, ztlv.ErrInvalidLength)
		}
	})

	t.Run("WriteErrorPropagation", func(t *testing.T) {
		for limit := 0; limit < 12; limit++ {
			w := &failAfterNWriter{limit: limit}
			enc := ztlv.NewEncoder(w)
			if err := enc.WriteTLVString(0x01, "payload"); err == nil {
				t.Fatalf("expected error at write limit %d", limit)
			}
		}
		w := &failAfterNWriter{limit: 0}
		enc := ztlv.NewEncoder(w)
		requireErrIs(t, enc.WriteNested(0x01, func(e *ztlv.Encoder) error {
			return e.WriteTLVUint8(0x02, 1)
		}), errSimulatedWrite)
	})
}

func TestSkipVariants(t *testing.T) {
	t.Parallel()

	// 1. Seekable bytes.Reader: normal skip, Skip(0), and EOF detection when truncated!
	var buf bytes.Buffer
	enc := ztlv.NewEncoder(&buf)
	requireNoErr(t, enc.WriteString("chunk1"))
	requireNoErr(t, enc.WriteString("chunk2_to_skip"))
	requireNoErr(t, enc.WriteString("chunk3"))

	dec := ztlv.NewDecoder(bytes.NewReader(buf.Bytes()))
	c1, err := dec.ReadString()
	requireNoErr(t, err)
	assertEq(t, "chunk1", c1)

	requireNoErr(t, dec.Skip(0))
	len2, err := dec.ReadLength()
	requireNoErr(t, err)
	requireNoErr(t, dec.Skip(len2))

	c3, err := dec.ReadString()
	requireNoErr(t, err)
	assertEq(t, "chunk3", c3)

	// Seekable EOF: seeking past end of bytes.Reader MUST return io.EOF, not nil.
	decTrunc := ztlv.NewDecoder(bytes.NewReader([]byte{1, 2, 3}))
	requireErrIs(t, decTrunc.Skip(10), io.EOF)

	// 2. Non-seeker stream: Skip & EOF.
	decNS := ztlv.NewDecoder(nonSeekerReader{r: bytes.NewReader(buf.Bytes())})
	_, err = decNS.ReadString()
	requireNoErr(t, err)
	requireNoErr(t, decNS.SkipTLV())
	c3ns, err := decNS.ReadString()
	requireNoErr(t, err)
	assertEq(t, "chunk3", c3ns)

	decNSEOF := ztlv.NewDecoder(nonSeekerReader{r: &bytes.Buffer{}})
	requireErrIs(t, decNSEOF.Skip(100), io.EOF)

	// 3. Seeker that returns error on Seek (like an OS pipe *os.File) falls back cleanly.
	decPipe := ztlv.NewDecoder(failingSeekerReader{r: bytes.NewReader(buf.Bytes())})
	_, err = decPipe.ReadString()
	requireNoErr(t, err)
	requireNoErr(t, decPipe.SkipTLV())
	c3pipe, err := decPipe.ReadString()
	requireNoErr(t, err)
	assertEq(t, "chunk3", c3pipe)

	// 4. MaxSkipSize enforcement.
	decLimit := ztlv.NewDecoder(&bytes.Buffer{})
	requireErrIs(t, decLimit.Skip(ztlv.DefaultMaxSkipSize+1), ztlv.ErrPayloadTooLarge)

	// 5. Nested SkipTLV regression test (no stack overflow / aliasing).
	buf.Reset()
	requireNoErr(t, enc.WriteNested(0xAA, func(e *ztlv.Encoder) error {
		if err := e.WriteTLVString(0x01, "hello"); err != nil {
			return err
		}
		return e.WriteTLVBytes(0x02, make([]byte, 10))
	}))
	decNested := ztlv.NewDecoder(nonSeekerReader{r: &buf})
	err = decNested.ReadNested(0xAA, func(d *ztlv.Decoder) error {
		v, err := d.ReadTLVString(0x01)
		requireNoErr(t, err)
		assertEq(t, "hello", v)
		tag, err := d.ReadTag()
		requireNoErr(t, err)
		assertEq(t, ztlv.Tag(0x02), tag)
		return d.SkipTLV()
	})
	requireNoErr(t, err)
}

func TestEOFAndErrorPaths(t *testing.T) {
	t.Parallel()

	// 1. ShortBufferError message and Encoder.Reset after WriteNested.
	sb := &ztlv.ShortBufferError{Required: 10, Available: 4}
	if !strings.Contains(sb.Error(), "need 10 bytes, got 4") {
		t.Fatalf("unexpected ShortBufferError string: %q", sb.Error())
	}

	var buf1, buf2 bytes.Buffer
	enc := ztlv.NewEncoder(&buf1)
	sentinel := errors.New("nested write error")
	err := enc.WriteNested(0x01, func(*ztlv.Encoder) error { return sentinel })
	requireErrIs(t, err, sentinel)
	enc.Reset(&buf2)
	requireNoErr(t, enc.WriteTLVUint8(0x02, 7))
	assertEq(t, 0, buf1.Len())
	assertEq(t, 6, buf2.Len())

	// 2. Every Read* method returns error cleanly on empty stream (io.EOF).
	empty := func() *ztlv.Decoder { return ztlv.NewDecoder(&bytes.Buffer{}) }
	eofChecks := []func(*ztlv.Decoder) error{
		func(d *ztlv.Decoder) error { _, e := d.ReadTag(); return e },
		func(d *ztlv.Decoder) error { _, e := d.ReadLength(); return e },
		func(d *ztlv.Decoder) error { _, e := d.ReadTime(); return e },
		func(d *ztlv.Decoder) error { _, e := d.ReadBool(); return e },
		func(d *ztlv.Decoder) error { _, e := d.ReadUint8(); return e },
		func(d *ztlv.Decoder) error { _, e := d.ReadUint16(); return e },
		func(d *ztlv.Decoder) error { _, e := d.ReadUint32(); return e },
		func(d *ztlv.Decoder) error { _, e := d.ReadUint64(); return e },
		func(d *ztlv.Decoder) error { _, e := d.ReadString(); return e },
		func(d *ztlv.Decoder) error { _, e := d.ReadBytes(); return e },
		func(d *ztlv.Decoder) error { _, e := d.ReadStrings(); return e },
		func(d *ztlv.Decoder) error { _, e := d.ReadStringsPrefixed(); return e },
		func(d *ztlv.Decoder) error { return d.ReadNestedBody(func(*ztlv.Decoder) error { return nil }) },
		func(d *ztlv.Decoder) error { return d.SkipTLV() },
	}
	for i, fn := range eofChecks {
		if err := fn(empty()); err == nil {
			t.Fatalf("eofCheck[%d] expected error, got nil", i)
		}
	}

	// 3. Every ReadTLV* method returns UnexpectedTagError when tag differs.
	tagMismatchChecks := []func(*ztlv.Decoder) error{
		func(d *ztlv.Decoder) error { _, e := d.ReadTLVBool(0x01); return e },
		func(d *ztlv.Decoder) error { _, e := d.ReadTLVUint8(0x01); return e },
		func(d *ztlv.Decoder) error { _, e := d.ReadTLVUint16(0x01); return e },
		func(d *ztlv.Decoder) error { _, e := d.ReadTLVUint32(0x01); return e },
		func(d *ztlv.Decoder) error { _, e := d.ReadTLVUint64(0x01); return e },
		func(d *ztlv.Decoder) error { _, e := d.ReadTLVInt8(0x01); return e },
		func(d *ztlv.Decoder) error { _, e := d.ReadTLVInt16(0x01); return e },
		func(d *ztlv.Decoder) error { _, e := d.ReadTLVInt32(0x01); return e },
		func(d *ztlv.Decoder) error { _, e := d.ReadTLVInt64(0x01); return e },
		func(d *ztlv.Decoder) error { _, e := d.ReadTLVFloat32(0x01); return e },
		func(d *ztlv.Decoder) error { _, e := d.ReadTLVFloat64(0x01); return e },
		func(d *ztlv.Decoder) error { _, e := d.ReadTLVString(0x01); return e },
		func(d *ztlv.Decoder) error { _, e := d.ReadTLVBytes(0x01); return e },
		func(d *ztlv.Decoder) error { _, e := d.ReadTLVBytesInto(0x01, make([]byte, 4)); return e },
		func(d *ztlv.Decoder) error { _, e := d.ReadTLVTime(0x01); return e },
		func(d *ztlv.Decoder) error { _, e := d.ReadTLVStrings(0x01); return e },
		func(d *ztlv.Decoder) error { return d.ReadNested(0x01, func(*ztlv.Decoder) error { return nil }) },
	}
	for i, fn := range tagMismatchChecks {
		dec := ztlv.NewDecoder(bytes.NewReader([]byte{0x02}))
		if err := fn(dec); !errors.Is(err, ztlv.ErrInvalidTag) {
			t.Fatalf("tagMismatchChecks[%d] expected ErrInvalidTag, got %v", i, err)
		}
	}

	// 4. Truncated payloads on ReadBytes, ReadString, ReadTLVBytesInto length, and ReadTLVStrings max payload.
	var b bytes.Buffer
	_ = ztlv.NewEncoder(&b).WriteLength(10)
	_, _ = b.Write([]byte{1, 2})
	_, err = ztlv.NewDecoder(bytes.NewReader(b.Bytes())).ReadBytes()
	requireErrIs(t, err, io.ErrUnexpectedEOF)

	_, err = ztlv.NewDecoder(bytes.NewReader(b.Bytes())).ReadString()
	requireErrIs(t, err, io.ErrUnexpectedEOF)

	_, err = ztlv.NewDecoder(bytes.NewReader([]byte{0x01})).ReadTLVBytesInto(0x01, make([]byte, 4))
	requireErrIs(t, err, io.EOF)

	b.Reset()
	e2 := ztlv.NewEncoder(&b)
	requireNoErr(t, e2.WriteTag(0x01))
	requireNoErr(t, e2.WriteLength(500))
	d2 := ztlv.NewDecoder(&b)
	d2.MaxListCount = 2
	d2.MaxStringSize = 10
	_, err = d2.ReadTLVStrings(0x01)
	requireErrIs(t, err, ztlv.ErrPayloadTooLarge)
}

// --- FUZZING (Security Proof) ---

func FuzzDecoder(f *testing.F) {
	f.Add([]byte{0x01, 0x00, 0x00, 0x00, 0x05, 'H', 'e', 'l', 'l', 'o'})
	f.Add([]byte{0x02, 0x00, 0x00, 0x00, 0x08, 0, 0, 0, 0, 0, 0, 0, 42})
	f.Add([]byte{0xAA, 0x00, 0x00, 0x00, 0x06, 0x01, 0x00, 0x00, 0x00, 0x01, 'a'})

	f.Fuzz(func(_ *testing.T, data []byte) {
		// Exercise tag-switch decode loop on seekable reader.
		dec := ztlv.NewDecoder(bytes.NewReader(data))
		for i := 0; i < 16; i++ {
			tag, err := dec.ReadTag()
			if err != nil {
				break
			}
			switch tag {
			case 0x01:
				_, _ = dec.ReadString()
			case 0x02:
				_, _ = dec.ReadUint64Prefixed()
			case 0x03:
				_, _ = dec.ReadTimePrefixed()
			case 0x04:
				_, _ = dec.ReadStringsPrefixed()
			case 0xAA:
				_ = dec.ReadNestedBody(func(nd *ztlv.Decoder) error {
					_, err := nd.ReadTag()
					if err != nil {
						return err
					}
					return nd.SkipTLV()
				})
			default:
				_ = dec.SkipTLV()
			}
		}

		// Also exercise direct raw decode methods on non-seeker reader.
		dec2 := ztlv.NewDecoder(nonSeekerReader{r: bytes.NewReader(data)})
		_, _ = dec2.ReadBytes()
		_, _ = dec2.ReadTime()
		_, _ = dec2.ReadStrings()
		if len(data) > 0 {
			_ = dec2.Skip(uint32(data[0]))
		}
	})
}

// --- BENCHMARKS (Performance Proof) ---

func BenchmarkWriteUint64(b *testing.B) {
	var buf bytes.Buffer
	enc := ztlv.NewEncoder(&buf)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf.Reset()
		_ = enc.WriteUint64(12345678)
	}
}

func BenchmarkReadUint64(b *testing.B) {
	var buf bytes.Buffer
	_ = ztlv.NewEncoder(&buf).WriteUint64(12345678)
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

func BenchmarkWriteString(b *testing.B) {
	var buf bytes.Buffer
	enc := ztlv.NewEncoder(&buf)
	payload := "Standard string for benchmark purposes"
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf.Reset()
		_ = enc.WriteString(payload)
	}
}

func BenchmarkReadString(b *testing.B) {
	var buf bytes.Buffer
	_ = ztlv.NewEncoder(&buf).WriteString("Standard string for benchmark purposes")
	data := buf.Bytes()
	reader := bytes.NewReader(data)
	dec := ztlv.NewDecoder(reader)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reader.Reset(data)
		_, _ = dec.ReadString()
	}
}

func BenchmarkReadBytes(b *testing.B) {
	var buf bytes.Buffer
	_ = ztlv.NewEncoder(&buf).WriteBytes(make([]byte, 1024))
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

func BenchmarkReadBytesInto_ZeroAlloc(b *testing.B) {
	var buf bytes.Buffer
	_ = ztlv.NewEncoder(&buf).WriteBytes(make([]byte, 1024))
	data := buf.Bytes()
	reader := bytes.NewReader(data)
	dec := ztlv.NewDecoder(reader)
	reuseBuf := make([]byte, 1024)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reader.Reset(data)
		length, _ := dec.ReadLength()
		_, _ = dec.ReadBytesInto(length, reuseBuf)
	}
}

func BenchmarkReadBytesInto_Pool(b *testing.B) {
	const payloadSize = 1024
	pool := &sync.Pool{
		New: func() any {
			buf := make([]byte, payloadSize)
			return &buf
		},
	}
	var buf bytes.Buffer
	_ = ztlv.NewEncoder(&buf).WriteBytes(make([]byte, payloadSize))
	data := buf.Bytes()
	reader := bytes.NewReader(data)
	dec := ztlv.NewDecoder(reader)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reader.Reset(data)
		length, _ := dec.ReadLength()
		bufPtr := pool.Get().(*[]byte)
		_, _ = dec.ReadBytesInto(length, *bufPtr)
		pool.Put(bufPtr)
	}
}

func BenchmarkSkipTLV(b *testing.B) {
	var buf bytes.Buffer
	_ = ztlv.NewEncoder(&buf).WriteTLVBytes(0x01, make([]byte, 256))
	data := buf.Bytes()
	reader := bytes.NewReader(data)
	dec := ztlv.NewDecoder(reader)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reader.Reset(data)
		_, _ = dec.ReadTag()
		_ = dec.SkipTLV()
	}
}

func BenchmarkSkipTLV_Network(b *testing.B) {
	var buf bytes.Buffer
	_ = ztlv.NewEncoder(&buf).WriteTLVBytes(0x01, make([]byte, 256))
	data := buf.Bytes()
	reader := bytes.NewReader(data)
	ns := nonSeekerReader{r: reader}
	dec := ztlv.NewDecoder(ns)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reader.Reset(data)
		_, _ = dec.ReadTag()
		_ = dec.SkipTLV()
	}
}

func BenchmarkRoundtrip_Primitive(b *testing.B) {
	const tag = ztlv.Tag(0x01)
	var buf bytes.Buffer
	enc := ztlv.NewEncoder(&buf)
	dec := ztlv.NewDecoder(&buf)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf.Reset()
		enc.Reset(&buf)
		_ = enc.WriteTLVUint64(tag, 9876543210)
		dec.Reset(&buf)
		_, _ = dec.ReadTLVUint64(tag)
	}
}

func BenchmarkRoundtrip_Message(b *testing.B) {
	const (
		tagID      = ztlv.Tag(0x01)
		tagName    = ztlv.Tag(0x02)
		tagCreated = ztlv.Tag(0x03)
		tagActive  = ztlv.Tag(0x04)
	)
	now := time.Now().UTC()
	name := "jean-baptiste.dupont"
	var buf bytes.Buffer
	enc := ztlv.NewEncoder(&buf)
	dec := ztlv.NewDecoder(&buf)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf.Reset()
		enc.Reset(&buf)
		_ = enc.WriteTLVUint64(tagID, 42)
		_ = enc.WriteTLVString(tagName, name)
		_ = enc.WriteTLVTime(tagCreated, now)
		_ = enc.WriteTLVBool(tagActive, true)
		dec.Reset(&buf)
		_, _ = dec.ReadTLVUint64(tagID)
		_, _ = dec.ReadTLVString(tagName)
		_, _ = dec.ReadTLVTime(tagCreated)
		_, _ = dec.ReadTLVBool(tagActive)
	}
}

func BenchmarkWriteNested(b *testing.B) {
	var buf bytes.Buffer
	enc := ztlv.NewEncoder(&buf)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf.Reset()
		_ = enc.WriteNested(0xAA, func(e *ztlv.Encoder) error {
			if err := e.WriteTLVUint64(0x01, 1234); err != nil {
				return err
			}
			return e.WriteTLVString(0x02, "alice")
		})
	}
}

func BenchmarkReadNested(b *testing.B) {
	var buf bytes.Buffer
	_ = ztlv.NewEncoder(&buf).WriteNested(0xAA, func(e *ztlv.Encoder) error {
		if err := e.WriteTLVUint64(0x01, 1234); err != nil {
			return err
		}
		return e.WriteTLVString(0x02, "alice")
	})
	data := buf.Bytes()
	reader := bytes.NewReader(data)
	dec := ztlv.NewDecoder(reader)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reader.Reset(data)
		_ = dec.ReadNested(0xAA, func(d *ztlv.Decoder) error {
			_, _ = d.ReadTLVUint64(0x01)
			_, _ = d.ReadTLVString(0x02)
			return nil
		})
	}
}
