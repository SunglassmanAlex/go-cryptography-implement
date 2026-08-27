package main

import (
	"Implement/crypto/ot/iknp"
	"fmt"
	"net"
)

func main() {
	senderConn, receiverConn := net.Pipe()
	done := make(chan bool)

	m0List := [][]byte{
		[]byte("m0-0"),
		[]byte("m0-1"),
	}
	m1List := [][]byte{
		[]byte("m1-0"),
		[]byte("m1-1"),
	}

	choices := []byte{0, 1}
	go func() {
		result, err := iknp.Receive(receiverConn, choices)
		if err != nil {
			fmt.Println("receiver error:", err)
		}
		for i, msg := range result {
			fmt.Printf("receiver[%d]=%q\n", i, msg)
		}
		done <- true
	}()

	go func() {
		err := iknp.Send(senderConn, m0List, m1List)
		if err != nil {
			fmt.Println("sender error:", err)
		}
		fmt.Println("sender done")
		done <- true
	}()

	<-done
	<-done
}
