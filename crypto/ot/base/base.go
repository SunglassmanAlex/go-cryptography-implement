package base

import (
	"Implement/crypto/elgamal"
	"errors"
	"fmt"
	"net"
)

func Send(conn net.Conn, m0, m1 []byte) error {
	pub0, err := elgamal.ReadPublicKey(conn)
	if err != nil {
		return fmt.Errorf("receive pub0: %w", err)
	}

	pub1, err := elgamal.ReadPublicKey(conn)
	if err != nil {
		return fmt.Errorf("receive pub1: %w", err)
	}

	ct0, err := pub0.EncryptBytes(m0)
	if err != nil {
		return err
	}
	ct1, err := pub1.EncryptBytes(m1)
	if err != nil {
		return err
	}

	if err := elgamal.WriteHybridCiphertext(conn, ct0); err != nil {
		return err
	}
	if err := elgamal.WriteHybridCiphertext(conn, ct1); err != nil {
		return err
	}

	return nil
}

func Receive(conn net.Conn, choice byte) ([]byte, error) {
	pub0 := new(elgamal.PublicKey)
	pub1 := new(elgamal.PublicKey)

	priv, pk0, err := elgamal.GenerateKey()
	if err != nil {
		return nil, errors.New("generate public and private key failed")
	}
	pk1, err := elgamal.GeneratePubKey()
	if err != nil {
		return nil, errors.New("generate public key failed")
	}

	switch choice {
	case byte(0):
		pub0 = pk0
		pub1 = pk1
	case byte(1):
		pub0 = pk1
		pub1 = pk0
	default:
		return nil, errors.New("choice not 0 or 1")
	}

	if err := elgamal.WritePublicKey(conn, pub0); err != nil {
		fmt.Println("Receiver send pub0 error: ", err)
		return nil, err
	}
	if err := elgamal.WritePublicKey(conn, pub1); err != nil {
		fmt.Println("Receiver send pub1 error: ", err)
		return nil, err
	}

	ct0, err := elgamal.ReadHybridCiphertext(conn)
	if err != nil {
		return nil, err
	}
	ct1, err := elgamal.ReadHybridCiphertext(conn)
	if err != nil {
		return nil, err
	}

	selectedCt := &ct0
	if choice == 1 {
		selectedCt = &ct1
	}

	msg, err := priv.DecryptBytes(*selectedCt)

	return msg, nil
}
