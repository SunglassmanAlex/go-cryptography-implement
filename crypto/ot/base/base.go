package base

import (
	"Implement/crypto/bn254util"
	"Implement/crypto/elgamal"
	"Implement/crypto/ot"
	"errors"
	"fmt"
	"net"

	"github.com/consensys/gnark-crypto/ecc/bn254"
)

func Send(conn net.Conn, m0, m1 []byte) error {
	enc := bn254.NewEncoder(conn)
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

	r0, err := bn254util.RandomNonZeroScalar()
	if err != nil {
		fmt.Println("Sender generate r0 failed")
		return err
	}
	r1, err := bn254util.RandomNonZeroScalar()
	if err != nil {
		fmt.Println("Sender generate r1 failed")
		return err
	}

	var C0, C1 bn254.G1Affine
	C0.ScalarMultiplicationBase(r0)
	C1.ScalarMultiplicationBase(r1)

	if err := enc.Encode(&C0); err != nil {
		return err
	}

	if err := enc.Encode(&C1); err != nil {
		return err
	}

	var shared0, shared1 bn254.G1Affine
	shared0.ScalarMultiplication(&pub0.Point, r0)
	shared1.ScalarMultiplication(&pub1.Point, r1)

	key0 := bn254util.KeyFromPoint(&shared0)
	key1 := bn254util.KeyFromPoint(&shared1)

	cipher0 := ot.XorBytes(m0, key0)
	cipher1 := ot.XorBytes(m1, key1)

	if err := ot.WriteBytes(conn, cipher0); err != nil {
		fmt.Println("Sender write cipher0 error:", err)
		return err
	}

	if err := ot.WriteBytes(conn, cipher1); err != nil {
		fmt.Println("Sender write cipher1 error:", err)
		return err
	}
	return nil
}

func Receive(conn net.Conn, choice byte) ([]byte, error) {
	enc := bn254.NewEncoder(conn)
	dec := bn254.NewDecoder(conn)

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

	var C0, C1 bn254.G1Affine

	if err := dec.Decode(&C0); err != nil {
		return nil, fmt.Errorf("receive C0: %w", err)
	}

	if err := dec.Decode(&C1); err != nil {
		return nil, fmt.Errorf("receive C1: %w", err)
	}

	cipher0, err := ot.ReadBytes(conn)
	if err != nil {
		return nil, err
	}

	cipher1, err := ot.ReadBytes(conn)
	if err != nil {
		return nil, err
	}

	selectedC := &C0
	selectedCipher := cipher0

	if choice == 1 {
		selectedC = &C1
		selectedCipher = cipher1
	}

	var shared bn254.G1Affine
	shared.ScalarMultiplication(selectedC, priv.X)

	key := bn254util.KeyFromPoint(&shared)
	message := ot.XorBytes(selectedCipher, key)
	return message, nil
}
