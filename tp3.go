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
var jchPeersAddr = "https://jch.irif.fr:8082/peers/"
var jchRootAddr = "https://jch.irif.fr:8082/peers/jch.irif.fr/root"



func main() {
	var n int //servira pour savoir le nombre d'octects écrits
	transport := &*http.DefaultTransport.(*http.Transport)
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	client := &http.Client{
		Transport: transport,
		Timeout:   50 * time.Second,
	}

	req, err := http.NewRequest("GET", jchPeersAddr, nil)
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

	req, err = http.NewRequest("GET", jchRootAddr, nil)
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

	fmt.Printf("rep adresse :\n%x\n", body)

	//######################################################################


	//message Hello : panic

	
	ext := make([]byte,4)
	var name string
	name = "panic" 
	hello := append(ext, []byte(name)... )
	
	Id := make([]byte,4)
	Id[0] = 0x4
	Id[1] = 0x8
	Id[2] = 0x15
	Id[3] = 0x16

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
	raddr, _ := net.ResolveUDPAddr("udp", serveurUrl)
	conn, errD := net.DialUDP("udp",nil, raddr)
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
	
	n,_, err = conn.ReadFromUDP(reponse)
	if err != nil {
		log.Fatalf("Read error %d", err)
		return
	}
	fmt.Printf("Number of byte copied:\n%d\n\n", n)
	fmt.Printf("Hello reply:\n%s\n\n", reponse)


	//reception de publicKey et création du message publicKeyReply
	publicKey := make([]byte, 1024)
	n,_, err = conn.ReadFromUDP(publicKey)
	if err != nil {
		log.Fatalf("Read error %d", err)
		return
	}
	fmt.Printf("Number of byte copied:\n%d\n\n", n)

	fmt.Printf("PublicKey:\n%s\n\n", publicKey[8:]) //Le body de publicKey comment à l'octet numéro 7

	fmt.Printf("PublicKeyID:\n%x\n\n", publicKey[:4])
	//publicKey[:4] sont les 4 premiers octets du paquet UDP, soit l'id ????

	fmt.Printf("PublicKeyReply\n\n")

	

	//récupération de l'ID pour le mettre dans publicKeyReply
	IdPub := publicKey[:4]
	//On fixe les autres paramètres
	Type[0] = 129
	Length[0] = 0
	Length[1] = 0

	publicKeyReply := append(append(append([]byte(IdPub), []byte(Type)...),[]byte(Length) ...))
	//On envoie le paquet
	_, err = conn.Write( publicKeyReply )  // _ = on ne donne pas de nom à la variable car on ne veut pas l'utiliser
	if err != nil {
		log.Fatalf("Write error %d", err)
		return
	}

	//écoute du root
	root := make([]byte, 1024)
	n,_, err = conn.ReadFromUDP(root)
	if err != nil {
		log.Fatalf("Read error %d", err)
		return
	}
	fmt.Printf("Number of byte copied in response root:\n%d\n\n", n)
	fmt.Printf("root:\n%x\n\n", root[7:39])
	//patched

	
	//envoi de notre hash(racine) : 0 pour le moment car on n'exporte aucun fichier
	
	Type[0] = 130 //c'est le type de rootReply
	hashEmptyRoot := make([]byte,32)
	binary.BigEndian.PutUint16(Length[0:], uint16(len(hashEmptyRoot)))

	//var hashEmptyRootStr string = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	//c'est sale de le faire à la main mais c'est pour le test
	binary.BigEndian.PutUint64(hashEmptyRoot[0:8], uint64(0xe3b0c44298fc1c14))
	binary.BigEndian.PutUint64(hashEmptyRoot[8:16], uint64(0x9afbf4c8996fb924))
	binary.BigEndian.PutUint64(hashEmptyRoot[16:24], uint64(0x27ae41e4649b934c))
	binary.BigEndian.PutUint64(hashEmptyRoot[24:32], uint64(0xa495991b7852b855))



	fmt.Printf("len(hash)=%d\n",len(hashEmptyRoot))
	fmt.Printf("hashEmptyRoot :\n0x%x\n\n",hashEmptyRoot[0:32])
	//fmt.Printf("0x%s\n\n",hashEmptyRootStr) //test pour vérifier que l'entrée a bien été faite
	rootMessage := append(append(append([]byte(Id), []byte(Type)...),[]byte(Length) ...),[]byte(hashEmptyRoot)...) //rootReply
	//On envoie le paquet
	n, err = conn.Write( rootMessage )  // _ = on ne donne pas de nom à la variable car on ne veut pas l'utiliser
	if err != nil {
		log.Fatalf("Write error %d", err)
		return
	}
	fmt.Printf("Written bytes in root message: %d\nNormaly 39 : 7 for the header and 32 for the hash\n\n", n)




	//test pour voir si on est bien enregistré et que l'on peut bien récupérer notre adresse
		//Récupération de l'adresse root de panic ( en réalité hash(&root) )
	fmt.Printf("Test du retour de notre propre adresse root\n\n")
	req, err = http.NewRequest("GET", "https://jch.irif.fr:8082/peers/panic/root", nil)
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

	fmt.Printf("rep adresse :\n%s\n",string(body)) //étrange pour le moment n'affiche rien..

}
