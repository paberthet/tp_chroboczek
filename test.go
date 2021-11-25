package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"time"
	//"io/outil"
	//"crypto/tls"
	//"net/http"
)

type Message struct {
	Id     []byte
	Type   []byte
	Length []byte
	Body   []byte
}

var serveurUrl = "jch.irif.fr:8082"
var jchPeersAddr = "https://jch.irif.fr:8082/peers/"
var jchRootAddr = "https://jch.irif.fr:8082/peers/jch.irif.fr/root"

func NewMessage(I []byte, T []byte, L []byte, B []byte) Message {
	Longueur := make([]byte, 2)
	if len(I) != 4 {
		log.Fatal("Invalid Id length on message initialisation")
	}
	if len(T) != 1 {
		log.Fatal("Invalid Type length on message initialisation")
	}
	if len(L) != 2 {
		log.Fatal("Invalid Length object on message initialisation")
	}
	binary.BigEndian.PutUint16(Longueur[0:], uint16(len(B)))
	if !bytes.Equal(Longueur, L) {
		log.Fatal("Invalid Body length on message initialisation")
	}
	mess := Message{I, T, L, B}
	return mess
}

func MessageToBytes(mess Message) []byte {
	ret := append(mess.Id, mess.Type...)
	ret = append(ret, mess.Length...)
	ret = append(ret, mess.Body...)
	return ret
}

func BytesToMessage(tab []byte) Message {
	mess := NewMessage(tab[:4], tab[4:5], tab[5:7], tab[7:])
	return mess
}

func ExtChecker(mess Message, ext uint32) bool {
	extmess := binary.BigEndian.Uint32(mess.Body[7:11])
	if extmess != ext {
		log.Printf("Unvalid extension : expected %v , got %v\n", ext, extmess)
		return false
	}
	return true
}

func TypeChecker(mess Message, typ int8) bool {
	typB := make([]byte, 1)
	typB[0] = byte(typ)
	if !bytes.Equal(mess.Type, typB) {
		log.Printf("Unvalid type : expected %v, got %v\n", typB, mess.Type)
		return false
	}
	return true
}

func MessageSender(conn *net.UDPConn, mess Message) {
	byt := MessageToBytes(mess)
	_, err := conn.Write(byt)
	if err != nil {
		log.Printf("Failed to send message %v to connexion %v", mess, conn)
		return
	}
}

func MessageListener(conn *net.UDPConn) Message {
	messB := make([]byte, 1024)
	err := conn.SetReadDeadline(time.Now().Add(2000 * time.Millisecond))
	if err != nil {
		log.Fatalf("Timeout Set error %d\n", err)
	}
	_, _, err = conn.ReadFromUDP(messB)
	if err != nil {
		log.Fatalf("Read error %d", err)
	}
	//on va tronquer messB car on risque des pbs de diff entre la longueur de messB (1024) et la longueur réelle du message
	upper := 7 + binary.BigEndian.Uint16(messB[5:7])
	mess := NewMessage(messB[:4], messB[4:5], messB[5:7], messB[7:upper])
	return mess
}

func main() {
	ext := make([]byte, 4)
	name := "panic"
	hello := append(ext, []byte(name)...)

	Id := make([]byte, 4)
	Id[0] = 0x4
	Id[1] = 0x8
	Id[2] = 0x15
	Id[3] = 0x16

	Type := make([]byte, 1)
	Type[0] = 0
	Length := make([]byte, 2)
	binary.BigEndian.PutUint16(Length[0:], uint16(len(hello)))

	mess := NewMessage(Id, Type, Length, hello)
	fmt.Printf("%v", mess)
	messO := MessageToBytes(mess)
	fmt.Printf("%v", messO)
	messM := BytesToMessage(messO)
	fmt.Printf("%v", messM)

	raddr, _ := net.ResolveUDPAddr("udp", serveurUrl)
	conn, errD := net.DialUDP("udp", nil, raddr)
	if errD != nil {
		log.Fatalf("Connection error %v\n", errD)
		return
	}
	defer conn.Close()

	MessageSender(conn, mess)
	respsonse := MessageListener(conn)
	fmt.Printf("%v \n", respsonse)
}
