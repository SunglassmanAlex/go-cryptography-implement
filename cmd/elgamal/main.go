package main

import (
	"Implement/crypto/bn254util"
	"Implement/crypto/elgamal"
	"fmt"
	"math/big"
	"net"

	"github.com/consensys/gnark-crypto/ecc/bn254"
)

func sender(conn net.Conn, done chan bool, msg *big.Int) {
	defer func() {
		_ = conn.Close()
		done <- true
	}()
	pub := new(elgamal.PublicKey)
	dec := bn254.NewDecoder(conn)
	dec.Decode(&pub.Point)
	messagePoint := bn254util.PointFromScalar(msg)
	ct, err := pub.Encrypt(messagePoint)
	if err != nil {
		fmt.Println("message point error: ", err)
		return
	}
	enc := bn254.NewEncoder(conn)
	enc.Encode(&ct.C1)
	enc.Encode(&ct.C2)
}

func receiver(conn net.Conn, done chan bool, expectedMsg *big.Int) {
	defer func() {
		_ = conn.Close()
		done <- true
	}()
	priv, pub, err := elgamal.GenerateKey()
	if err != nil {
		fmt.Println("Sender generate key error: ", err)
		return
	}
	enc := bn254.NewEncoder(conn)
	enc.Encode(&pub.Point)
	ct := new(elgamal.Ciphertext)
	dec := bn254.NewDecoder(conn)
	dec.Decode(&ct.C1)
	dec.Decode(&ct.C2)
	decrypted, err := priv.Decrypt(ct)
	if err != nil {
		fmt.Println("Decrypt failed: ", err)
		return
	}
	exp := bn254util.PointFromScalar(expectedMsg)
	if decrypted.Equal(&exp) {
		fmt.Println("Verify secceeded")
	} else {
		fmt.Println("Verify failed")
	}
}

func main() {
	senderConn, receiverConn := net.Pipe()
	done := make(chan bool)
	msg := big.NewInt(77)
	go sender(senderConn, done, msg)
	go receiver(receiverConn, done, msg)
	<-done
	<-done
}
