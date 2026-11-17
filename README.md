# ztlv

[![Go Reference](https://pkg.go.dev/badge/github.com/eraceo/ztlv/v2.svg)](https://pkg.go.dev/github.com/eraceo/ztlv/v2)
[![Go Report Card](https://goreportcard.com/badge/github.com/eraceo/ztlv/v2)](https://goreportcard.com/report/github.com/eraceo/ztlv/v2)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

`ztlv` is a secure, zero-dependency, low-allocation Tag-Length-Value (TLV) parser for Go.

It is designed for network protocols, binary framing, and high-throughput streaming systems where memory pressure and strict input validation are paramount. It operates directly on `io.Reader` and `io.Writer` interfaces, enabling streaming of payloads larger than available RAM.

## Design Principles

*   **Zero Dependencies**: Pure Go standard library — zero runtime and zero test dependencies.
*   **Security First**: Strict bounds checking (`MaxStringSize`, `MaxBytesSize`, `MaxListCount`, `MaxSkipSize`) prevents OOM and infinite-drain DoS attacks. Timestamps reject out-of-range nanoseconds (`>= 1e9`), and `Skip` validates EOF on both seekable and non-seekable streams.
*   **Low / Zero Allocation**: Fixed TLV headers and primitives are batched in stack-embedded scratch buffers (`17` bytes on `Encoder`, `12` bytes on `Decoder`). Reused `nestedBuf`/`nestedDec` and embedded `io.LimitedReader` fields eliminate per-call heap allocations.
*   **Optimized Strings**: Uses `unsafe.String` (Go 1.20+) to wrap the freshly allocated read buffer without a second heap copy.
*   **Robust Time**: Timestamps are stored as 96-bit (`int64` Seconds + `uint32` Nanoseconds, UTC) to avoid Y2038 and Y2262 limits.
*   **Big Endian**: All multi-byte numeric values and lengths use standard network byte order.

## Installation

```bash
go get github.com/eraceo/ztlv/v2
```

## Usage

### Encoder

The encoder wraps any `io.Writer`. Fixed-width `WriteTLV*` methods batch tag, length, and value into a single `Write` call with zero heap allocations.

```go
package main

import (
	"bytes"
	"time"

	"github.com/eraceo/ztlv/v2"
)

func main() {
	var buf bytes.Buffer
	enc := ztlv.NewEncoder(&buf)

	const (
		tagUser      ztlv.Tag = 0x01
		tagTimestamp ztlv.Tag = 0x02
		tagActive    ztlv.Tag = 0x03
	)

	// Write Tag + Length + Payload
	_ = enc.WriteTLVString(tagUser, "admin")
	_ = enc.WriteTLVTime(tagTimestamp, time.Now().UTC())
	_ = enc.WriteTLVBool(tagActive, true)
}
```

### Decoder (`ReadTag` Switch Loop)

Use `ReadTag()` together with `*Prefixed` methods (`ReadUint64Prefixed`, `ReadBoolPrefixed`, `ReadTimePrefixed`, `ReadStringsPrefixed`, `ReadNestedBody`, `ReadString`, `ReadBytes`) to handle optional, out-of-order, or unknown fields safely with `SkipTLV()`.

```go
package main

import (
	"errors"
	"io"
	"log"

	"github.com/eraceo/ztlv/v2"
)

func decodeStream(r io.Reader) error {
	const (
		tagUser      ztlv.Tag = 0x01
		tagTimestamp ztlv.Tag = 0x02
		tagUserID    ztlv.Tag = 0x03
	)

	dec := ztlv.NewDecoder(r)

	for {
		tag, err := dec.ReadTag()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}

		switch tag {
		case tagUser:
			val, err := dec.ReadString()
			if err != nil {
				return err
			}
			log.Printf("User: %s", val)
		case tagTimestamp:
			ts, err := dec.ReadTimePrefixed()
			if err != nil {
				return err
			}
			log.Printf("Timestamp: %s", ts)
		case tagUserID:
			id, err := dec.ReadUint64Prefixed()
			if err != nil {
				return err
			}
			log.Printf("ID: %d", id)
		default:
			// Unknown tag: reads Length and skips payload with 0 allocations.
			if err := dec.SkipTLV(); err != nil {
				return err
			}
		}
	}
}
```

When decoding fixed-order schemas, you can also use the `ReadTLV*` helpers (`ReadTLVString`, `ReadTLVUint64`, `ReadTLVTime`, `ReadTLVStrings`, `ReadNested`, etc.) which verify the expected tag automatically and return `*ztlv.UnexpectedTagError` (wrapping `ztlv.ErrInvalidTag`) on mismatch.

### Nested Containers

Use `WriteNested` and `ReadNested` (or `ReadNestedBody` inside a switch loop). Any unread trailing bytes inside a container are automatically drained (bounded by `MaxSkipSize`) so the parent stream stays aligned.

```go
err := enc.WriteNested(0xAA, func(inner *ztlv.Encoder) error {
	if err := inner.WriteTLVString(0x01, "Alice"); err != nil {
		return err
	}
	return inner.WriteTLVUint8(0x02, 30)
})
```

### Advanced: Zero-Allocation Byte Reading

For hot paths where GC pressure must be eliminated, reuse a buffer (for example from a `sync.Pool`) with `ReadBytesInto` or `ReadTLVBytesInto`. Both check `len(buf) >= length` (and `MaxBytesSize`) before consuming payload bytes from the stream, returning `*ztlv.ShortBufferError` (wrapping `ztlv.ErrShortBuffer`) if the slice is too short.

```go
// Pre-allocated buffer (with len == cap)
buf := make([]byte, 4096)

length, err := dec.ReadLength()
if err != nil {
	return err
}

if uint64(len(buf)) < uint64(length) {
	return ztlv.ErrShortBuffer
}

n, err := dec.ReadBytesInto(length, buf)
if err != nil {
	return err
}
process(buf[:n])
```

With `ReadTLVBytesInto`, if `errors.As(err, &shortErr)` matches `*ztlv.ShortBufferError`, you can allocate `make([]byte, shortErr.Required)` and recover the remaining payload immediately with `dec.ReadBytesInto(shortErr.Required, biggerBuf)`.

## Security Configuration

To prevent Denial of Service (DoS) attacks via malicious length prefixes or oversized unknown containers, the decoder enforces default sanity limits that can be adjusted per instance:

```go
dec := ztlv.NewDecoder(r)

dec.MaxStringSize = 64 * 1024        // Limit strings to 64 KiB (default: 1 MiB)
dec.MaxBytesSize  = 10 * 1024 * 1024 // Limit raw blobs to 10 MiB (default: 10 MiB)
dec.MaxListCount  = 5000             // Limit string list items (default: 1000)
dec.MaxSkipSize   = 10 * 1024 * 1024 // Limit Skip / nested drain (default: 10 MiB)
```

## Supported Types & Binary Format

| Component | Size | Type | Description |
|-----------|------|------|-------------|
| **Tag** | 1 byte | `uint8` | Identifier (`0x00`–`0xFF`). |
| **Length** | 4 bytes | `uint32` | Payload byte size (Big Endian). |
| **Value** | *N* bytes | Raw | Payload data. |

Supported types (raw `Write*`/`Read*`, `*Prefixed` decoder, and `WriteTLV*`/`ReadTLV*`):
- Integers: `uint8`, `uint16`, `uint32`, `uint64`, `int8`, `int16`, `int32`, `int64`
- Floats: `float32`, `float64` (IEEE 754 Big Endian)
- Boolean: `bool` (1 byte: `0x01` true, `0x00` false)
- Time: `time.Time` (12 bytes: `int64` seconds + `uint32` nanoseconds `[0, 999999999]`, returned in UTC)
- Slices & Text: `[]byte`, `string`, `[]string`
- Containers: nested TLV streams via `WriteNested` / `ReadNested` / `ReadNestedBody`

**String List TLV Format (`WriteTLVStrings` / `ReadTLVStrings`)**:
- `Tag` (1B) + `TotalPayloadBytes` (`uint32`, 4B) + `Count` (`uint32`, 4B) + `[Len_i (4B) + Bytes_i]...`
- Storing `TotalPayloadBytes` in the TLV `Length` header ensures `SkipTLV()` can skip unknown string lists safely without desynchronizing the stream.

## Performance

Benchmarks measured on AMD Ryzen 9 7900 (`linux/amd64`, Go 1.22.2):

| Operation | Time | Allocs |
|-----------|------|--------|
| `WriteUint64` | 3.44 ns | 0 |
| `ReadUint64` | 5.86 ns | 0 |
| `WriteString` (~38B) | 8.03 ns | 0 |
| `ReadString` (~38B) | 26.16 ns | 1 |
| `ReadBytes` (1KB) | 139.4 ns | 1 |
| `ReadBytesInto` (1KB, reuse) | 18.25 ns | 0 |
| `ReadBytesInto` (1KB, `sync.Pool`) | 23.28 ns | 0 |
| `SkipTLV` (256B, seekable) | 16.75 ns | 0 |
| `SkipTLV` (256B, non-seekable stream) | 32.61 ns | 0 |
| `Roundtrip_Primitive` (`uint64`) | 22.69 ns | 0 |
| `Roundtrip_Message` (4 fields) | 101.9 ns | 1 |
| `WriteNested` (2 fields, warm) | 19.44 ns | 0 |
| `ReadNested` (2 fields, warm) | 63.23 ns | 1* |

*\*The single allocation in `ReadNested` comes from `ReadTLVString` inside the callback; `ReadNested` itself performs 0 allocations after first-call initialization.*
