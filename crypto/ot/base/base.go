package base

import (
	"Implement/crypto/elgamal"
	"errors"
	"fmt"
	"net"

	"github.com/consensys/gnark-crypto/ecc/bn254"
)

func Send(conn net.Conn, m0, m1 []byte) error {
	// enc := bn254.NewEncoder(conn)
	dec := bn254.NewDecoder(conn)

	pub0 := new(elgamal.PublicKey)
	pub1 := new(elgamal.PublicKey)

	if err := dec.Decode(&pub0.Point); err != nil {
		fmt.Println("Sender read pub0 error")
		return err
	}
	if err := dec.Decode(&pub1.Point); err != nil {
		fmt.Println("Sender read pub1 error")
		return err
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
	enc := bn254.NewEncoder(conn)
	// dec := bn254.NewDecoder(conn)

	pub0 := new(elgamal.PublicKey)
	pub1 := new(elgamal.PublicKey)
	priv := new(elgamal.PrivateKey)

	switch choice {
	case byte(0):
		var err error
		priv, pub0, err = elgamal.GenerateKey()
		if err != nil {
			return nil, errors.New("generate public and private key failed")
		}
		pub1, err = elgamal.GeneratePubKey()
		if err != nil {
			return nil, errors.New("generate public key failed")
		}
	case byte(1):
		var err error
		priv, pub1, err = elgamal.GenerateKey()
		if err != nil {
			return nil, errors.New("generate public and private key failed")
		}
		pub0, err = elgamal.GeneratePubKey()
		if err != nil {
			return nil, errors.New("generate public key failed")
		}
	default:
		return nil, errors.New("choice not 0 or 1")
	}

	if err := enc.Encode(&pub0.Point); err != nil {
		fmt.Println("Receiver send pub0 error: ", err)
		return nil, err
	}
	if err := enc.Encode(&pub1.Point); err != nil {
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
