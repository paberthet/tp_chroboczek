package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
)

type Message struct {
	Id     []byte
	Type   []byte
	Length []byte
	Body   []byte
}

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
	mess = BytesToMessage(messO)
	fmt.Printf("%v", mess)
}