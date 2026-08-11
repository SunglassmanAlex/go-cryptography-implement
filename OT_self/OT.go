package main

import (
	"crypto/rand"
	"crypto/sha256"
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

func keyFromPoint(p *bn254.G1Affine) []byte {
	raw := p.RawBytes()
	h := sha256.Sum256(raw[:])
	return h[:]
}

func alice(conn net.Conn, done chan bool, choice int) {
	defer func() {
		_ = conn.Close()
		done <- true
	}()
	enc := bn254.NewEncoder(conn)
	dec := bn254.NewDecoder(conn)
	k, err := randomNonZeroScalar()
	var C bn254.G1Affine
	if err := dec.Decode(&C); err != nil {
		fmt.Println("Alice receive C error: ", err)
		return
	}
	if err != nil {
		fmt.Println("Alice generate k failed: ", err)
		return
	}
	var K bn254.G1Affine
	K.ScalarMultiplicationBase(k)
	var pk0, pk1 bn254.G1Affine
	if choice == 0 {
		pk0.Set(&K)
		pk1.Sub(&C, &pk0)
	} else {
		pk1.Set(&K)
		pk0.Sub(&C, &pk1)
	}
	if err := enc.Encode(&pk0); err != nil {
		fmt.Println("Alice receive pk0 error: ", err)
		return
	}
	if err := enc.Encode(&pk1); err != nil {
		fmt.Println("Alice receive pk1 error: ", err)
		return
	}
}

func bob(conn net.Conn, done chan bool, m0, m1 []byte) {
	defer func() {
		_ = conn.Close()
		done <- true
	}()
	enc := bn254.NewEncoder(conn)
	dec := bn254.NewDecoder(conn)
	c, err := randomNonZeroScalar()
	if err != nil {
		fmt.Println("Bob random error: ", err)
		return
	}
	var C bn254.G1Affine
	C.ScalarMultiplicationBase(c) // C = cG
	if err := enc.Encode(&C); err != nil {
		fmt.Println("Bob send C error: ", err)
		return
	}
	var pk0, pk1 bn254.G1Affine
	if err := dec.Decode(&pk0); err != nil {
		fmt.Println("Bob read pk0 error: ", err)
		return
	}
	if err := dec.Decode(&pk1); err != nil {
		fmt.Println("Bob read pk1 error: ", err)
		return
	}
	var sum bn254.G1Affine
	sum.Add(&pk0, &pk1)
	if !sum.Equal(&C) {
		fmt.Println("Bob verify failed")
		return
	}
	fmt.Println("Bob verify success")
}

func main() {
	aliceConn, bobConn := net.Pipe()
	done := make(chan bool)

	choice := 1
	m0 := []byte("message zero")
	m1 := []byte("message one")
	go alice(aliceConn, done, choice) // receiver
	go bob(bobConn, done, m0, m1)     // sender
	<-done
	<-done
}
