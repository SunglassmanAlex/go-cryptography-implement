package main

import (
	"fmt"
	"net"
)

func alice(conn net.Conn, done chan bool) {
	defer conn.Close()
	msg := "Hello Golang"
	_, err := conn.Write([]byte(msg))
	if err != nil {
		fmt.Println("Alice send error: ", err)
	}
	done <- true
}

func bob(conn net.Conn, done chan bool) {
	defer conn.Close()
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		fmt.Println("Bob read error: ", err)
		done <- true
		return
	}
	fmt.Println("Bob received: ", string(buf[:n]))
	//fmt.Println("Bob received: ", buf[:n])
	done <- true
}

func main() {
	aliceConn, bobConn := net.Pipe()
	done := make(chan bool)
	go alice(aliceConn, done)
	go bob(bobConn, done)
	<-done
	<-done
}
