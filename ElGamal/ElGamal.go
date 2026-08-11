package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"net"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

func randomNonZeroScalar() (*big.Int, error) {
	for {
		k, err := rand.Int(rand.Reader, fr.Modulus())
		if err != nil {
			return nil, err
		}
		if k.Sign() != 0 {
			return k, nil
		}
	}
}

func pointFromScalar(s *big.Int) bn254.G1Affine {
	var p bn254.G1Affine
	p.ScalarMultiplicationBase(s)
	return p
}

func alice(conn net.Conn, done chan bool, expectedScalar *big.Int) {
	defer func() {
		_ = conn.Close()
		done <- true
	}()
	x, err := randomNonZeroScalar()
	if err != nil {
		fmt.Println("Alice keygen error: ", err)
		return
	}

	enc := bn254.NewEncoder(conn)
	dec := bn254.NewDecoder(conn)

	var pub bn254.G1Affine
	pub.ScalarMultiplicationBase(x)
	fmt.Println("Alice Public Key: ", pub.String())

	if err := enc.Encode(&pub); err != nil {
		fmt.Println("Alice send public key error: ", err)
		return
	}

	var c1, c2 bn254.G1Affine
	if err := dec.Decode(&c1); err != nil {
		fmt.Println("Alice read c1 error: ", err)
		return
	}
	if err := dec.Decode(&c2); err != nil {
		fmt.Println("Alice read c2 error: ", err)
		return
	}

	var shared, decrypted bn254.G1Affine
	shared.ScalarMultiplication(&c1, x)
	decrypted.Sub(&c2, &shared)

	expectedPoint := pointFromScalar(expectedScalar)

	if decrypted.Equal(&expectedPoint) {
		fmt.Println("Alice verify, success")
	} else {
		fmt.Println("Alice verify, failed")
	}
}

func bob(conn net.Conn, done chan bool, messageScalar *big.Int) {
	defer func() {
		_ = conn.Close()
		done <- true
	}()

	dec := bn254.NewDecoder(conn)
	enc := bn254.NewEncoder(conn)

	var pub bn254.G1Affine
	if err := dec.Decode(&pub); err != nil {
		fmt.Println("Bob read public key error: ", err)
		return
	}
	fmt.Println("Bob received public key: ", pub.String())
	k, err := randomNonZeroScalar()
	if err != nil {
		fmt.Println("Bob random error: ", err)
		return
	}
	msgPoint := pointFromScalar(messageScalar)

	var c1, c2, shared bn254.G1Affine
	c1.ScalarMultiplicationBase(k)
	shared.ScalarMultiplication(&pub, k)
	c2.Add(&msgPoint, &shared)

	if err := enc.Encode(&c1); err != nil {
		fmt.Println("Bob send c1 error: ", err)
		return
	}
	if err := enc.Encode(&c2); err != nil {
		fmt.Println("Bob send c2 error: ", err)
		return
	}
}

func main() {
	aliceConn, bobConn := net.Pipe()
	done := make(chan bool)
	messageScalar := big.NewInt(42)
	go alice(aliceConn, done, messageScalar)
	go bob(bobConn, done, messageScalar)
	<-done
	<-done
}
