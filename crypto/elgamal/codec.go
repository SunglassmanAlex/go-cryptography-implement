package elgamal

import (
	"Implement/crypto/transport"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/consensys/gnark-crypto/ecc/bn254"
)

func WriteHybridCiphertext(conn net.Conn, ct *HybridCiphertext) error {
	enc := bn254.NewEncoder(conn)

	if err := enc.Encode(&ct.C1); err != nil {
		return err
	}
	return transport.WriteBytes(conn, ct.Cipher)
}

func ReadHybridCiphertext(conn net.Conn) (*HybridCiphertext, error) {
	dec := bn254.NewDecoder(conn)
	ct := new(HybridCiphertext)

	if err := dec.Decode(&ct.C1); err != nil {
		return nil, err
	}

	cipher, err := transport.ReadBytes(conn)
	if err != nil {
		return nil, err
	}
	ct.Cipher = cipher

	return ct, nil
}

func WritePublicKey(w io.Writer, pub *PublicKey) error {
	if pub == nil {
		return errors.New("nil public key")
	}

	enc := bn254.NewEncoder(w)
	if err := enc.Encode(&pub.Point); err != nil {
		return fmt.Errorf("encode public key: %w", err)
	}

	return nil
}

func ReadPublicKey(r io.Reader) (*PublicKey, error) {
	pub := new(PublicKey)

	dec := bn254.NewDecoder(r)
	if err := dec.Decode(&pub.Point); err != nil {
		return nil, fmt.Errorf("decode public key: %w", err)
	}

	return pub, nil
}
