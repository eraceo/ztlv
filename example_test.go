package ztlv_test

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/eraceo/ztlv/v2"
)

func ExampleEncoder() {
	var buf bytes.Buffer
	enc := ztlv.NewEncoder(&buf)

	const (
		tagUser      ztlv.Tag = 0x01
		tagTimestamp ztlv.Tag = 0x02
		tagActive    ztlv.Tag = 0x03
	)

	_ = enc.WriteTLVString(tagUser, "admin")
	_ = enc.WriteTLVTime(tagTimestamp, time.Unix(1700000000, 0).UTC())
	_ = enc.WriteTLVBool(tagActive, true)

	fmt.Printf("encoded %d bytes\n", buf.Len())
	// Output:
	// encoded 33 bytes
}

func ExampleDecoder_switchLoop() {
	const (
		tagName    ztlv.Tag = 0x01
		tagID      ztlv.Tag = 0x02
		tagCreated ztlv.Tag = 0x03
		tagUnknown ztlv.Tag = 0x99
	)

	var buf bytes.Buffer
	enc := ztlv.NewEncoder(&buf)
	_ = enc.WriteTLVString(tagName, "alice")
	_ = enc.WriteTLVBytes(tagUnknown, []byte("future-extension"))
	_ = enc.WriteTLVUint64(tagID, 42)
	_ = enc.WriteTLVTime(tagCreated, time.Unix(1700000000, 0).UTC())

	dec := ztlv.NewDecoder(&buf)
	var name string
	var id uint64
	var created time.Time

	for {
		tag, err := dec.ReadTag()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			panic(err)
		}

		switch tag {
		case tagName:
			name, err = dec.ReadString()
		case tagID:
			id, err = dec.ReadUint64Prefixed()
		case tagCreated:
			created, err = dec.ReadTimePrefixed()
		default:
			err = dec.SkipTLV()
		}
		if err != nil {
			panic(err)
		}
	}

	fmt.Printf("%s %d %s\n", name, id, created.Format(time.RFC3339))
	// Output:
	// alice 42 2023-11-14T22:13:20Z
}

func ExampleDecoder_ReadBytesInto() {
	var buf bytes.Buffer
	enc := ztlv.NewEncoder(&buf)
	_ = enc.WriteBytes([]byte("zero-alloc payload"))

	dec := ztlv.NewDecoder(&buf)
	scratch := make([]byte, 64)

	length, err := dec.ReadLength()
	if err != nil {
		panic(err)
	}
	n, err := dec.ReadBytesInto(length, scratch)
	if err != nil {
		panic(err)
	}

	fmt.Printf("%s\n", scratch[:n])
	// Output:
	// zero-alloc payload
}

func ExampleEncoder_WriteNested() {
	const (
		tagUser ztlv.Tag = 0xAA
		tagName ztlv.Tag = 0x01
		tagAge  ztlv.Tag = 0x02
	)

	var buf bytes.Buffer
	enc := ztlv.NewEncoder(&buf)

	err := enc.WriteNested(tagUser, func(inner *ztlv.Encoder) error {
		if err := inner.WriteTLVString(tagName, "Alice"); err != nil {
			return err
		}
		return inner.WriteTLVUint8(tagAge, 30)
	})
	if err != nil {
		panic(err)
	}

	dec := ztlv.NewDecoder(&buf)
	err = dec.ReadNested(tagUser, func(inner *ztlv.Decoder) error {
		name, err := inner.ReadTLVString(tagName)
		if err != nil {
			return err
		}
		age, err := inner.ReadTLVUint8(tagAge)
		if err != nil {
			return err
		}
		fmt.Printf("%s (%d)\n", name, age)
		return nil
	})
	if err != nil {
		panic(err)
	}
	// Output:
	// Alice (30)
}
