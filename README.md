# ztlv

[![Go Reference](https://pkg.go.dev/badge/github.com/eraceo/ztlv.svg)](https://pkg.go.dev/github.com/eraceo/ztlv)
[![Go Report Card](https://goreportcard.com/badge/github.com/eraceo/ztlv)](https://goreportcard.com/report/github.com/eraceo/ztlv)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

`ztlv` is a secure, low-allocation Tag-Length-Value (TLV) parser for Go.

It is designed for network protocols, critical infrastructure, and high-throughput systems where memory pressure and input validation are paramount. It operates directly on `io.Reader` and `io.Writer` interfaces, enabling streaming of datasets larger than available RAM.

## Design Principles

*   **Security First**: Strict bounds checking prevents OOM (Out-Of-Memory) attacks. Integers are checked for overflows.
*   **Low Allocation**: Primitives (Tags, Lengths, Time) are encoded/decoded using stack-allocated scratchpads.
*   **Optimized Strings**: Uses `unsafe.String` (Go 1.20+) to convert byte buffers to strings without additional heap copying.
*   **Robust Time**: Timestamps are stored as 96-bit (64-bit Seconds + 32-bit Nanoseconds) to prevent Y2262 issues and maintain precision.
*   **Big Endian**: All numeric values conform to standard network byte order.

## Installation

```bash
go get github.com/eraceo/ztlv
```

## Usage

### Encoder

The encoder wraps an `io.Writer`. It performs no heap allocations for primitive types.

```go
package main

import (
	"bytes"
	"time"
	"github.com/eraceo/ztlv"
)

func main() {
	var buf bytes.Buffer
	enc := ztlv.NewEncoder(&buf)

	// Write Tag (0x01) + Length + String
	_ = enc.WriteTLVString(0x01, "admin")

	// Write Tag (0x02) + Length + Time (12 bytes)
	_ = enc.WriteTLVTime(0x02, time.Now())
}
```

### Decoder

The decoder wraps an `io.Reader` and enforces configurable limits.

```go
package main

import (
	"bytes"
	"log"
	"github.com/eraceo/ztlv"
)

func main() {
	// r is your io.Reader (e.g., net.Conn or bytes.Buffer)
	dec := ztlv.NewDecoder(r)

	// Decode loop
	tag, err := dec.ReadTag()
	if err != nil {
		log.Fatal(err)
	}

	switch tag {
	case 0x01:
		// Efficiently reads string (1 allocation only)
		val, _ := dec.ReadString()
		log.Printf("User: %s", val)
	case 0x02:
		// Efficiently reads Length + Time (0 allocation)
		// Uses ReadTimePrefixed because WriteTLVTime includes a length.
		ts, _ := dec.ReadTimePrefixed()
		log.Printf("Timestamp: %s", ts)
	default:
		// Efficiently skip unknown tags without allocation
		len, _ := dec.ReadLength()
		_ = dec.Skip(len)
	}
}
```

### Advanced: Zero-Allocation Byte Reading

For hot paths where garbage collection pressure must be eliminated, use `ReadBytesInto` with a reused buffer. This method separates length reading from payload reading to ensure stream integrity.

```go
// Pre-allocated buffer (or retrieved from sync.Pool)
buf := make([]byte, 4096)
// 1. Read the length first
length, err := dec.ReadLength()
if err != nil {
    handleError(err)
}

// 2. Check if buffer is large enough
if uint32(cap(buf)) < length {
    // Handle error, or grow buffer
    handleError(fmt.Errorf("buffer too small"))
}

// 3. Read payload directly into the slice (Zero Allocation)
err = dec.ReadBytesInto(length, buf)
if err != nil {
    handleError(err)
}

process(buf[:length])
```

## Security Configuration

To prevent Denial of Service (DoS) attacks via malicious length prefixes, the decoder enforces default sanity limits. These can be adjusted per instance.

```go
dec := ztlv.NewDecoder(r)

// Adjust limits based on your protocol requirements
dec.MaxStringSize = 64 * 1024       // Limit strings to 64KB
dec.MaxBytesSize  = 10 * 1024 * 1024 // Limit raw blobs to 10MB
dec.MaxListCount  = 5000            // Limit list items
```

## Binary Format Specification

| Component | Size | Type | Description |
|-----------|------|------|-------------|
| **Tag** | 1 byte | `uint8` | Identifier (0-255). |
| **Length** | 4 bytes | `uint32` | Payload size in bytes (Big Endian). |
| **Value** | *N* bytes | Raw | Payload data. |

**Time Format**: Stored as 12 bytes.
- Bytes 0-7: Seconds (`int64`, Big Endian)
- Bytes 8-11: Nanoseconds (`uint32`, Big Endian)

## Performance

*   **Primitives**: 0 allocs/op.
*   **Strings**: 1 alloc/op (buffer only, no string copy).
*   **Bytes**: 1 alloc/op (or 0 if using `ReadBytesInto`).
*   **Skip**: 0 allocs/op (uses `io.Discard`).