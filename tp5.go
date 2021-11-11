package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"time"
)

func main() {
	var address string
	flag.StringVar(&address, "address", ":8082", "UDP listening address")
	flag.Parse()

	conn, err := net.ListenPacket("udp", address)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	buf := make([]byte, 1500)
	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			log.Printf("ReadFrom: %v", err)
			continue
		}

		if n < 7 {
			log.Printf("Truncated packet")
			continue
		}

		if buf[4] != 0 {
			log.Printf("Unknown message %v", buf[4])
			continue
		}

		now := time.Now().Format("15:04")
		body := []byte(fmt.Sprintf("Il est %v.", now))
		buf2 := make([]byte, 4+1+2+len(body))
		copy(buf2[:4], buf)
		buf2[4] = 1
		buf2[5] = byte(len(body) >> 8)
		buf2[6] = byte(len(body) & 0xFF)
		copy(buf2[7:], body)

		_, err = conn.WriteTo(buf2, addr)
		if err != nil {
			log.Printf("WriteTo: %v", err)
		}
	}
}

