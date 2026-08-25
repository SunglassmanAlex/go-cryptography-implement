package ot

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const maxMessageSize = 1 << 20 // 最大允许 1 MiB

func WriteBytes(w io.Writer, data []byte) error {
	if len(data) > maxMessageSize {
		return fmt.Errorf("message too large: %d bytes", len(data))
	}

	var lengthBuf [4]byte
	binary.BigEndian.PutUint32(lengthBuf[:], uint32(len(data)))

	if err := writeFull(w, lengthBuf[:]); err != nil {
		return fmt.Errorf("write message length: %w", err)
	}

	if err := writeFull(w, data); err != nil {
		return fmt.Errorf("write message data: %w", err)
	}

	return nil
}

func ReadBytes(r io.Reader) ([]byte, error) {
	var lengthBuf [4]byte

	if _, err := io.ReadFull(r, lengthBuf[:]); err != nil {
		return nil, fmt.Errorf("read message length: %w", err)
	}

	length := binary.BigEndian.Uint32(lengthBuf[:])
	if length > maxMessageSize {
		return nil, fmt.Errorf("message too large: %d bytes", length)
	}

	data := make([]byte, int(length))

	if _, err := io.ReadFull(r, data); err != nil {
		return nil, fmt.Errorf("read message data: %w", err)
	}

	return data, nil
}

func writeFull(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)

		if n > 0 {
			data = data[n:]
		}

		if err != nil {
			return err
		}

		if n == 0 {
			return errors.New("writer made no progress")
		}
	}

	return nil
}
