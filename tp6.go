package main

import (
	"fmt"
	"log"
	"net"
	"time"
)

func main() {
	buff := make([]byte,1)
	conn, err := net.Dial("udp", "lulu:8081")
	if err != nil {
		log.Fatalf("Connection error%d\n", err);
		return
	}
	buff[0] = 0
	_, err = conn.Write(buff) // _ = on ne donne pas de nom à la variable car on ne veut pas l'utiliser
	if err != nil {
		log.Fatalf("Write error %d", err)
		return
	}
	err = conn.SetReadDeadline(time.Now().Add(2000*time.Millisecond))
	if err != nil {
		log.Fatalf("Timeout Set error %d\n",err)
		return
	}
	reponse := make([]byte,1024)
	_, err  = conn.Read(reponse)
	if err != nil {
		log.Fatalf("Read error %d", err)
		return
	}
	fmt.Printf("\n\n%s\n\n", reponse)
}

