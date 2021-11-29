package main

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"time"
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

//================================================================================
//						UDP Message
//================================================================================

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

func ErrorMessageSender(mess Message, str string, conn *net.UDPConn) { // génère message d'erreur à partir d'un message erroné
	mess.Type[0] = byte(254)
	tmp := []byte(str)
	mess.Body = tmp
	binary.BigEndian.PutUint16(mess.Length[0:], uint16(len(tmp)))
	MessageSender(conn, mess)
}

func TypeChecker(mess Message, typ int16) bool {
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

//=====================================================================================
//						API REST
//=====================================================================================

//Method = "GET", ou "POST", ou ...
func httpRequest(method, addr string, client http.Client) ([]byte, error) {
	req, err := http.NewRequest(method, addr, nil)
	bodyIfErr := make([]byte, 1)

	if err != nil {
		log.Printf("NewRequest: %v", err)
		return bodyIfErr, err
	}

	r, err := client.Do(req)
	if err != nil {
		log.Printf("Get: %v", err)
		return bodyIfErr, err
	}

	body, err := ioutil.ReadAll(r.Body)
	r.Body.Close()

	if err != nil {
		log.Printf("Read: %v", err)
		return bodyIfErr, err
	}

	return body, nil
}

func parsePrint(body []byte, toPrint string) [][]byte {
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
		fmt.Printf("%v %v: %v\n", i, toPrint, string(id))
	}
	return ids
}

func PeerSelector([][]byte) {
	/*
		ici on prend en paramètre le tableau peer adresses et on demande au user le peer auquel il veut se connecter. Puis on lance la connexion UDP avec ce peer
	*/
	return
}

//===================================================================================================
//									Merkle s tree
//===================================================================================================

func TreeParser() {
	return
}

func TreeChecker() {
	return
}

//====================================================================================================
//								Sécurité
//====================================================================================================

func DHKeyExchange() {
	/*
		ici on génère g^a , on l'envoie via un message avec un type (qu il faudra réserver sur la mailing list), et on attend le reply qui contient g^b. Le return contient le secret partagé
	*/
	return
}

func AESEncrypt() []byte {
	/*
		AES-256 en CBC ou GSM. Pour avoir une clé de 256bits, on fait un SHA256 du secret partagé (SHA256 output 256 bits non?)
	*/
	return nil
}

func AESDecrypt() []byte {
	return nil
}

//==================================================================================================
func main() {

	//Préparation des requettes REST
	transport := &*http.DefaultTransport.(*http.Transport)
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	client := &http.Client{
		Transport: transport,
		Timeout:   50 * time.Second,
	}

	//Récupération des pairs
	body, err := httpRequest("GET", jchPeersAddr, *client)
	if err != nil {
		log.Fatalf("Error get peers : %v\n", err)
		return
	}

	//affichage des pairs
	parsePrint(body, "peers")

	//Récupération de root de jch
	body, err = httpRequest("GET", jchRootAddr, *client)
	if err != nil {
		log.Fatalf("Error get root : %v\n", err)
		return
	}

	//affichage de root
	log.Printf("\n\nroot : %v\n\n", body)

	hashEmptyRoot := make([]byte, 32)
	//var hashEmptyRootStr string = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	//c'est sale de le faire à la main mais c'est pour le test
	binary.BigEndian.PutUint64(hashEmptyRoot[0:8], uint64(0xe3b0c44298fc1c14))
	binary.BigEndian.PutUint64(hashEmptyRoot[8:16], uint64(0x9afbf4c8996fb924))
	binary.BigEndian.PutUint64(hashEmptyRoot[16:24], uint64(0x27ae41e4649b934c))
	binary.BigEndian.PutUint64(hashEmptyRoot[24:32], uint64(0xa495991b7852b856 /*5*/))

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

	helloMess := NewMessage(Id, Type, Length, hello)

	raddr, _ := net.ResolveUDPAddr("udp", serveurUrl)
	conn, errD := net.DialUDP("udp", nil, raddr)
	if errD != nil {
		log.Fatalf("Connection error %v\n", errD)
		return
	}
	defer conn.Close()

	MessageSender(conn, helloMess)
	response := MessageListener(conn)
	fmt.Printf("%v \n", response)

	if !TypeChecker(response, 128) {
		ErrorMessageSender(response, "Bad type\n", conn)
	}

	//Publickey + PublicKeyReply

	response = MessageListener(conn)
	if !TypeChecker(response, 1) {
		ErrorMessageSender(response, "Bad type\n", conn)
	}
	fmt.Printf("%v \n", response)
	response.Type[0] = byte(129)
	MessageSender(conn, response)

	//root + rootReply

	response = MessageListener(conn)
	if !TypeChecker(response, 2) {
		ErrorMessageSender(response, "Bad type\n", conn)
	}
	fmt.Printf("%v \n", response)
	response.Body = hashEmptyRoot
	response.Type[0] = byte(130)

	MessageSender(conn, response)
}
