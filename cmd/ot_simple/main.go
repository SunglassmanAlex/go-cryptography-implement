package main

import (
	"Implement/crypto/ot/base"
	"fmt"
	"net"
)

func main() {
	senderConn, receiverConn := net.Pipe()
	defer senderConn.Close()
	defer receiverConn.Close()

	m0 := []byte("00000000")
	m1 := []byte("11111111")
	choice := byte(0)

	senderDone := make(chan error, 1)
	receiverDone := make(chan struct {
		message []byte
		err     error
	}, 1)

	go func() {
		senderDone <- base.Send(senderConn, m0, m1)
	}()

	go func() {
		message, err := base.Receive(receiverConn, choice)
		receiverDone <- struct {
			message []byte
			err     error
		}{message, err}
	}()

	if err := <-senderDone; err != nil {
		fmt.Println("sender failed:", err)
		return
	}

	result := <-receiverDone
	if result.err != nil {
		fmt.Println("receiver failed:", result.err)
		return
	}

	fmt.Println("received:", string(result.message))
}
