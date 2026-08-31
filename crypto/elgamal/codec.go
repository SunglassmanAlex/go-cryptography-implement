package elgamal

import (
	"Implement/crypto/transport"
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
