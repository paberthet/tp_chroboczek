package main

import (
	"io/ioutil"
	"log"
	"net"
	"net/http"

	//"net"
	"time"
	//"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"encoding/binary"
)
/*
type message struct {
	Id   uint32
	Type uint8
	Length  uint16
	Body []byte
}*/
var serveurUrl = "jch.irif.fr:8082"
var chatUrl = "https://jch.irif.fr:8082/peers/"
var chatUrladdr = "https://jch.irif.fr:8082/peers/jch.irif.fr/root"

func main() {
	transport := &*http.DefaultTransport.(*http.Transport)
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	client := &http.Client{
		Transport: transport,
		Timeout:   50 * time.Second,
	}

	req, err := http.NewRequest("GET", chatUrl, nil)
	if err != nil {
		log.Printf("NewRequest: %v", err)
		return
	}

	r, err := client.Do(req)
	if err != nil {
		log.Printf("Get: %v", err)
		return
	}

	body, err := ioutil.ReadAll(r.Body)
	r.Body.Close()

	if err != nil {
		log.Printf("Read: %v", err)
		return
	}

	//parser

	ids := bytes.Split(body, []byte{byte('\n')})
	//fmt.Printf("%v\n",string(ids[0]))

	if len(ids) > 0 {
		//fmt.Printf("len(ids) : %d", len(ids))
		last := len(ids) - 1
		if len(ids[last]) == 0 {
			ids = ids[:last]
			/*attention ids = isd [a,b] veut dire que dans ids, on ne garde que les éléments
			d'indices allant de a jusqu'à b-1. Avant correction de ids=ids[:last-1],
			ids devenait vide et c'est pour cela que rien n'était affiché.
			En fait dans le TP initial on devait perdre à chaque fois le dernier message
			car le derier id étai tsupprimé en même temps que le cararactère \n
			qui symbolisait la fin de la liste
			*/
		}
		//fmt.Printf("len(ids) : %d", len(ids))
	}

	for i, id := range ids {
		fmt.Printf("peers %v: %v\n", i, string(id))

	}

	fmt.Printf("\nRécupération du hash de root\n\n")

	//Récupération de l'adresse root de jch.irif.fr ( en réalité hash(&root) )

	req, err = http.NewRequest("GET", chatUrladdr, nil)
	if err != nil {
		log.Printf("NewRequest: %v", err)
		return
	}

	r, err = client.Do(req)
	if err != nil {
		log.Printf("Get: %v", err)
		return
	}

	body, err = ioutil.ReadAll(r.Body)
	r.Body.Close()

	if err != nil {
		log.Printf("Read: %v", err)
		return
	}

	fmt.Printf("rep adresse :\n%s\n", string(body))

	//######################################################################


	//message Hello
	
	ext := make([]byte,4)
	var name string
	name = "panic" 
	hello := append(ext, []byte(name)... )
	
	Id := make([]byte, 4)
	Id[3] = 1
	Type := make([]byte,1)
	Type[0] = 0
	Length := make([]byte,2)
	binary.BigEndian.PutUint16(Length[0:], uint16(len(hello)))


	//b := make([]byte, 8)
	//binary.LittleEndian.PutUint64(b, uint64(i))
	
	/*
	var data message
	data.Id = 1 //Il faut juste que ce soit différent de 0
	data.Type = 0
	data.Length = uint16(len(hello))
	data.Body = hello
	*/


	//buff := make([]byte, 1)
	//raddr, _ := net.ResolveUDPAddr("udp", chatUrl)
	conn, errD := net.Dial("udp", serveurUrl)
	if errD != nil {
		log.Fatalf("Connection error%d\n", err)
		return
	}
	defer conn.Close()
	//buff[0] = 0

	Message := append(append(append([]byte(Id), []byte(Type)...),[]byte(Length) ...), hello ...)

	_, err = conn.Write( Message )  // _ = on ne donne pas de nom à la variable car on ne veut pas l'utiliser
	if err != nil {
		log.Fatalf("Write error %d", err)
		return
	}
	err = conn.SetReadDeadline(time.Now().Add(2000 * time.Millisecond))
	if err != nil {
		log.Fatalf("Timeout Set error %d\n", err)
		return
	}
	reponse := make([]byte, 1024)
	_, err = conn.Read(reponse)
	if err != nil {
		log.Fatalf("Read error %d", err)
		return
	}
	fmt.Printf("\n\n%s\n\n", reponse)
}
