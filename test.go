package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
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
var jchAddr = "https://jch.irif.fr:8082/peers/jch.irif.fr/addresses"

var Id = []byte{byte(0x4), byte(0x8), byte(0xf), byte(0x10)}

/*
Idée:
est ce qu'on ne ferait pas une fonction écoute, lancée par un go au début du programme,
et qui écoute en boucle si on recoit des messages ou non, et si elle recoit un message elle réagit
en fonction du type qu'elle lit dans le message reçu (une sorte de switch)?

Par contre il faudrait retirer les log.Fatalf de MessageListner et lui faire retourner err en plus,
sinon à la première écoute sans réponse ça va crasher,
Ou alors ne pas définir de Deadline sur l'écoute ?
*/

//================================================================================
//						UDP Message
//================================================================================

func UDPInit(url string) *net.UDPConn {
	raddr, _ := net.ResolveUDPAddr("udp", url)
	conn, errD := net.DialUDP("udp", nil, raddr)
	if errD != nil {
		log.Fatalf("Connection error %v\n", errD)
	}
	return conn
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

func NATTravMessage(peeraddr [][]byte, conn *net.UDPConn) bool {
	T := make([]byte, 1)
	T[0] = byte(133)
	L := make([]byte, 2)
	binary.BigEndian.PutUint16(L[0:], uint16(18))
	B := make([]byte, 18)
	mess := NewMessage(Id, T, L, B)
	checker := false
	cmptr := 0

	/*

		//préparation en amont du message Hello,
		ext := make([]byte, 4)
		name := "panic"
		hello := append(ext, []byte(name)...)

		Type := make([]byte, 1)
		Type[0] = 0
		Length := make([]byte, 2)
		binary.BigEndian.PutUint16(Length[0:], uint16(len(hello)))

		helloMess := NewMessage(Id, Type, Length, hello)
		//Fin préparation du Hello
	*/

	for !checker && (cmptr < len(peeraddr)) {
		addr, _ := net.ResolveUDPAddr("udp", string(peeraddr[cmptr]))
		fmt.Printf("len : %v addr : %v addr bytes : %v\n", len(addr.IP), addr.IP, []byte(addr.IP))
		test_port := make([]byte, 2)
		binary.BigEndian.PutUint16(test_port[0:], uint16(addr.Port))
		fmt.Printf("port : %v port bytes %v\n", addr.Port, test_port)

		//Ok c'est bon, en fait la conversion en ipv4 mapped se fait toute seule par UDP resolve
		port := make([]byte, 2)
		binary.BigEndian.PutUint16(port[0:], uint16(addr.Port))
		ip := append([]byte(addr.IP), port...)
		mess.Body = ip

		fmt.Printf("Message construit : %v\n\n", mess)

		/*

			//Envoie de la requette de traversée de NAT au serveur
			MessageSender(conn, mess)
			//Attente que la demande soit transmise au client par le serveur
			time.Sleep(1*time.Second)
			//Envoi d'un Hello au client
			connP2P, errD := net.DialUDP("udp", nil, addr) //On ne peut pas faire appel à UDPinit telle qu'elle est définie actuellement
			if errD == nil {
				defer connP2P.Close() //Bizarre de faire ça là en sachant qu'on ne pourra pas y faire appel en dehors, il faudrait peut être renvoyer l'adresse avec laquell eon a réussi à traverser le NAT plutôt qu'un bool

				//Envoi du Hello
				MessageSender(connP2P, helloMess)
				//Ecoute si Hello du client
				rep := MessageListener(conn) //Pb ici, on voudrait pouvoir passer à la suite si on n'a pas de retour, mais ici à cause des log.Fatalf ça va crash si on n'a pas de retour
				//si on a un retour
					rep.Type[0]=128 //type de hello reply, on utilise rep car il y a deja le bon id dedans
					MessageSender(connP2P, rep)
					//on peut aussi écouter le helloReply qu'on est censés recevoir en retour de notre hello
					rep = MessageListener(connP2P)
					//à ce moment là le NAT est traversé, on peut dialoguer directement avec le client, je pense qu'il faudrait faire un return connP2P
			}
			//et sinon, si on n'a pas réussi les étapes précédentes, on passe à l'adresse suivante.

		*/

		cmptr++
	}
	return checker
}

func checkHash(mess Message) bool {
	check := sha256.Sum256(mess.Body[32:])
	return bytes.Equal(check[:], mess.Body[:32])
}

//Fonctionne sur un file, test en cours sur un BigFile
func collectDataFile(mess Message, conn *net.UDPConn, out *[]byte) { //c'est en fait un deep first search
	if !TypeChecker(mess, 131) { //Il faut que ce soit un message Datum
		//ErrorMessageSender(response, "Bad type\n", conn)
	}
	dataType := mess.Body[32] //c'est à cet endroit qu'est codé le type de data, après les 32 premiers octet du hash de notre requette
	if dataType == 2 {        //On est dans un directory
		log.Printf("You are not in a File or BigFile\n")
		return
	}
	if dataType == 1 { //On est dans un BigFile
		nbNodes := (binary.BigEndian.Uint16(mess.Length) - 33) / 32 //le - 33 est du au fait que la réponse contient le hash que l'on a demandé, ensuite dans un chunk, il n'y a que des hash, pas de noms d'où la division par 32 et non 64
		for i := 0; i < int(nbNodes); i++ {
			//Faire getdatum
			Type := make([]byte, 1)
			Type[0] = 3 //getDatum
			Length := make([]byte, 2)
			binary.BigEndian.PutUint16(Length[0:], uint16(32)) //Lenght = 32

			giveMeData := NewMessage(Id, Type, Length, mess.Body[33+32*i:33+32*(i+1)])

			MessageSender(conn, giveMeData)
			response := MessageListener(conn)
			if !checkHash(response) {
				log.Printf("Bad hash")
				return
			}
			//on checke le hash

			collectDataFile(response, conn, out)
		}
		return
	} else { //dataType = 0 on est donc dans un chunk
		*out = append(*out, mess.Body[33:]...)
		return
	}

}

//=====================================================================================
//						API REST
//=====================================================================================

//Method = "GET", ou "POST", ou ...
func HttpRequest(method, addr string, client http.Client) ([]byte, error) {
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

func ParseREST(body []byte) [][]byte {
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

	return ids
}

func PeerSelector(ids [][]byte, client http.Client) [][]byte {
	for i, id := range ids {
		fmt.Printf("%v %v: %v\n", i, "peers", string(id))
	}
	//scanf
	j := 0
	addr := jchPeersAddr + string(ids[j]) + "/addresses"
	reponse, err := HttpRequest("GET", addr, client)
	if err != nil {
		log.Fatalf("Error get peers addresses: %v\n", err)
	}
	reponse2 := ParseREST(reponse)
	return reponse2
}

//===================================================================================================
//									Merkle s tree
//===================================================================================================

type Node struct {
	content   []byte
	checksum  []byte
	chunk     bool
	directory bool
	root      *Node
	son       []Node
}

func NewNode(cont []byte, checksum []byte, chu bool, dir bool, roo *Node, tab []Node) (Node, error) {
	var err error
	err = nil
	if len(cont) > 128 && !dir {
		err = errors.New("content is more than 1024 bits")
	}
	if len(tab) > 32 && !dir {
		err = errors.New("parent of too many nodes")
	}
	checks := sha256.Sum256(cont)
	if !bytes.Equal(checks[:], checksum) {
		err = errors.New("invalid hash")
	}
	nod := Node{cont, checksum, chu, dir, roo, tab}
	return nod, err
}

func FileParser(filepath string) [][]byte {
	//subdivise un fichier en chunks de 1024 bits recursivement
	var tamp []byte
	buf, err := os.ReadFile(filepath)
	if err != nil {
		log.Panic(err)
	}
	ret := make([][]byte, 0, len(buf)/128+1)
	for len(buf) >= 128 {
		tamp, buf = buf[:128], buf[128:]
		ret = append(ret, tamp)
	}
	if len(buf) > 0 {
		ret = append(ret, buf)
	}
	return ret
}

//il nous faut une ou des fonctions pour construire l arbre
//eventuellement aussi de nouveaux struct

func BytesToChunk(byt []byte) Node {
	check := sha256.Sum256(byt)
	nod, err := NewNode(byt, check[:], true, false, nil, nil)
	if err != nil {
		log.Printf("Error while building leafs : %v", err)
	}
	return nod
}

func TreeChecker() bool {
	return false
}

//====================================================================================================
//								Sécurité
//====================================================================================================

func PubKeyToByte(pub ecdsa.PublicKey) []byte {
	x := pub.X.Bytes()
	x = x[:32]
	y := pub.Y.Bytes()
	y = y[:32]
	ret := append(x, y...)
	return ret
	//ici on considère que la courbe est le standard P256
}

func ByteToPubKey(b []byte) ecdsa.PublicKey {
	var pub ecdsa.PublicKey
	pub.Curve = elliptic.P256()
	x := new(big.Int)
	y := new(big.Int)
	x.SetBytes(b[:32])
	pub.X = x
	y.SetBytes(b[32:])
	pub.Y = y
	return pub
}

func ECDHGen(I []byte, T []byte) (Message, ecdsa.PrivateKey) {
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Printf("Error initializing private key ECDH")
	}
	public := private.PublicKey
	B := PubKeyToByte(public)
	L := make([]byte, 2)
	binary.BigEndian.PutUint16(L[0:], uint16(len(B)))
	return NewMessage(I, T, L, B), *private
}

func ECDHSharedGen(mess Message, privat ecdsa.PrivateKey) []byte {
	pub := ByteToPubKey(mess.Body)
	shared, _ := pub.Curve.ScalarMult(pub.X, pub.Y, privat.D.Bytes())
	return shared.Bytes()
}

func AESEncrypt(dh []byte, data []byte, addata []byte) []byte {
	/*
		AES-256 en CBC ou GCM. Pour avoir une clé de 256bits, on fait un SHA256 du secret partagé (SHA256 output 256 bits non?)
	*/
	key := sha256.Sum256(dh)
	c, err := aes.NewCipher(key[:])
	if err != nil {
		log.Printf("Error while initializing AES Encrypt : %v\n", err)
	}
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		log.Printf("Error while initializing GCM Mode Enc: %v\n", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		log.Printf("Error while initializing GCM Nonce Enc: %v\n", err)
	}
	return gcm.Seal(nonce, nonce, data, addata) //attention, dans l exemple que g pris addata = nil. A voir ce qu'on peut mettre ici pour l authentification gcm
}

func AESDecrypt(dh []byte, data []byte, addata []byte) []byte {
	key := sha256.Sum256(dh)
	c, err := aes.NewCipher(key[:])
	if err != nil {
		log.Printf("Error while initializing AES Decrypt : %v\n", err)
	}
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		log.Printf("Error while initializing GCM Mode Dec: %v\n", err)
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		log.Printf("Error on ciphertext length in AES Decrypt : doesn t match GCM Nonce size")
	}
	nonce, data := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, data, addata)
	if err != nil {
		log.Printf("Error while decrypting : %v\n", err)
	}
	return plaintext
}

//===================================================================================================
//                                SUBROUTINES
//===================================================================================================

func HelloRepeater(conn *net.UDPConn) {
	ext := make([]byte, 4)
	name := "panic"
	hello := append(ext, []byte(name)...)

	Type := make([]byte, 1)
	Type[0] = 0
	Length := make([]byte, 2)
	binary.BigEndian.PutUint16(Length[0:], uint16(len(hello)))

	helloMess := NewMessage(Id, Type, Length, hello)
	for {
		MessageSender(conn, helloMess)
		response := MessageListener(conn)

		if !TypeChecker(response, 128) {
			ErrorMessageSender(response, "Bad type\n", conn)
		}
		time.Sleep(30 * time.Second)
	}
}

func dataReceiver() {
	//Récup des pairs REST

	//Affichage pairs

	//Choix du pair scanf

	//Récup adresses pair REST

	//Tentative de co à l'une des adresses du pair (UDP)

	//Si co continue, sinon on revient au début avec message impossible to connect

	//Recup root pair REST (On ne le fait que si on a établi la co UDP, sinon cela ne nous servira à rien)

	//On est dans un directory, et tant qu'on est dans un directory
	//Où voulez vous aller? Scanf
	//UDP givedata
	//Affichage

	//On a atteint un file ou un big file
	//recup de la donnee

}

//==================================================================================================
func main() {
	var peertable [][]byte
	var wg sync.WaitGroup
	/*Partie dédiée à des tests temporaires========================================================
	text := []byte("Un petit texte tout mignon tout plein à chiffrer qui je l espère fait plus de 256 bits")
	key := []byte("YOLO")
	cipher := AESEncrypt(key, text, []byte("randomtext"))
	fmt.Printf("%v\n", bytes.Equal(text, AESDecrypt(key, cipher, []byte("radomtext"))))  //false
	fmt.Printf("%v\n", bytes.Equal(text, AESDecrypt(key, cipher, []byte("randomtext")))) //true
	I := make([]byte, 4)
	T := make([]byte, 1)
	T[0] = byte(13)
	mess := ECDHGen(I, T)
	fmt.Printf("%v\n %v\n", mess.Body[:32], mess.Body[32:])
	pub := ByteToPubKey(mess.Body)
	fmt.Printf("x =%v\n y=%v\n curve =%v\n", pub.X, pub.Y, pub.Curve)
	byt := PubKeyToByte(pub)
	fmt.Printf("%v\n %v\n", byt[:32], byt[32:])
	log.Fatalf("End of temporary tests")*/
	/*
		==========================================================================================*/

	//Préparation des requettes REST
	transport := http.DefaultTransport.(*http.Transport)
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	client := &http.Client{
		Transport: transport,
		Timeout:   50 * time.Second,
	}

	//Récupération des pairs
	body, err := HttpRequest("GET", jchPeersAddr, *client)
	if err != nil {
		log.Fatalf("Error get peers : %v\n", err)
		return
	}
	//affichage des pairs
	peertable = ParseREST(body)

	peertable = PeerSelector(peertable, *client)

	//Récupération de root de jch
	body, err = HttpRequest("GET", jchRootAddr, *client)
	if err != nil {
		log.Fatalf("Error get root : %v\n", err)
		return
	}

	//affichage de root
	log.Printf("\n\nroot : %v\n\n", body)
	hash := body

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

	Type := make([]byte, 1)
	Type[0] = 0
	Length := make([]byte, 2)
	binary.BigEndian.PutUint16(Length[0:], uint16(len(hello)))

	helloMess := NewMessage(Id, Type, Length, hello)

	conn := UDPInit(serveurUrl)
	defer conn.Close()

	MessageSender(conn, helloMess)
	response := MessageListener(conn)

	if !TypeChecker(response, 128) {
		ErrorMessageSender(response, "Bad type\n", conn)
	}

	//Publickey + PublicKeyReply

	response = MessageListener(conn)
	if !TypeChecker(response, 1) {
		ErrorMessageSender(response, "Bad type\n", conn)
	}
	response.Type[0] = byte(129)
	MessageSender(conn, response)

	//root + rootReply

	response = MessageListener(conn)
	if !TypeChecker(response, 2) {
		ErrorMessageSender(response, "Bad type\n", conn)
	}
	response.Body = hashEmptyRoot
	response.Type[0] = byte(130)
	MessageSender(conn, response)

	wg.Add(1)
	go HelloRepeater(conn)
	defer wg.Done()
	NATTravMessage(peertable, conn)

	wg.Wait()

	//######################################################################################################################################################################

	//Test d'accès aux données de jch
	//Récup des adresses de jch
	body, err = HttpRequest("GET", jchAddr, *client)
	if err != nil {
		log.Fatalf("Error get adresses : %v\n", err)
		return
	}
	addressesTable := ParseREST(body)
	//affichage des adresses
	log.Printf("\n\nadresses : %v\n\n", string(addressesTable[0])) //Une en IPv4
	//log.Printf("\n\nadresses : %v\n\n", string(addressesTable[1])) //Une en IPv6

	//On va tester l'IPv4

	connP2P := UDPInit(string(addressesTable[0]))
	defer connP2P.Close()

	MessageSender(connP2P, helloMess)   //Il faut d'abord dire bonjour, sinon pas content
	response = MessageListener(connP2P) //Helloreply
	if !TypeChecker(response, 128) {
		//ErrorMessageSender(response, "Bad type\n", conn)
	}
	//pubKey
	response = MessageListener(connP2P)
	if !TypeChecker(response, 1) {
		//ErrorMessageSender(response, "Bad type\n", conn)
	}
	fmt.Printf("Pubkey jch : %v\n", response.Body) //Jch n'utilise pas de pubkey
	//Pubkeyreply
	response.Type[0] = byte(129)
	MessageSender(connP2P, response)

	//Root / rootreply  Apparement, il faut le faire aussi entre pairs .. c'est bizarre vu qu'on l'a déjà fait avec le serveur mais bon
	response = MessageListener(connP2P)
	if !TypeChecker(response, 2) {
		//ErrorMessageSender(response, "Bad type\n", conn)
	}
	response.Body = hashEmptyRoot
	response.Type[0] = byte(130)
	MessageSender(connP2P, response)

	Type[0] = 3                                        //getDatum
	binary.BigEndian.PutUint16(Length[0:], uint16(32)) //Lenght = 32

	giveMeData := NewMessage(Id, Type, Length, hash)
	//fmt.Printf("%v \n", giveMeData)
	MessageSender(connP2P, giveMeData)
	response = MessageListener(connP2P)
	if !TypeChecker(response, 131) { //La première fois je me suis pris un : 254 --> please hello first, je suis pas poly j'ai pas dit boujour
		log.Printf("No datum..\n")
	}

	data_type := response.Body[32]
	if data_type == 0 {
		fmt.Printf("\nC'est un chunk\n")
	} else if data_type == 1 {
		fmt.Printf("\nC'est un bigfile\n")
	} else {
		fmt.Printf("\nC'est un directory\n")
	}

	nb_node := (binary.BigEndian.Uint16(response.Length) - 33) / 64 //le - 33 est du au fait que la réponse contient le hash que l'on a demandé, suivi d'un 2 (est-ici que le type de node est codé?)
	fmt.Printf("Body node number : \n%v\n", nb_node)                //Jch ne signe pas, alors c'est quoi ces octets à la fin???

	fmt.Printf("Body rep get datum : \n%v\n", response.Body)

	//Il faut parser la réponse
	for i := 0; uint16(i) < nb_node; i++ {
		fmt.Printf("élément %v : %v\n", i, string(response.Body[33+64*i:33+64*i+32]))
	}
	/*
		//Imaginons qu'on veuille README, c'est le 1 donc on prend le premier hash --> bizarre il a un coeff 2 comme si c'était un directory
		giveMeData.Body = response.Body[33+64*1-32 : 33+64*1] //Le 1 dans 33+64*1 - 32 et de 33 + 64*1 correspond au 1 du premier élément de la liste
		fmt.Printf("\ngiveMeData : \n%v \n", giveMeData)
		MessageSender(connP2P, giveMeData)
		response = MessageListener(connP2P)
		if !TypeChecker(response, 131) {
			log.Printf("No datum..\n")
		}

		fmt.Printf("Body rep get datum : \n%v\n", response.Body)
		data_type = response.Body[32]
		if data_type == 0 {
			fmt.Printf("\nC'est un chunk\n")
		} else if data_type == 1 {
			fmt.Printf("\nC'est un bigfile\n")
		} else {
			fmt.Printf("\nC'est un directory\n")
		}

		fmt.Printf("Body rep get datum : \n%v\n", response.Body)
		fmt.Printf("Et le README est :\n%v\n", string(response.Body[33:]))
	*/
	//Imaginons que l'on veuille aller dans images
	giveMeData.Body = response.Body[33+64*3-32 : 33+64*3] //Le 1 dans 33+32*1 et de 33+32*(1+2) correspond au 1 du premier élément de la liste

	fmt.Printf("\ngiveMeData : \n%v \n", giveMeData)
	MessageSender(connP2P, giveMeData)
	response = MessageListener(connP2P)
	nb_node = (binary.BigEndian.Uint16(response.Length) - 33) / 64
	for i := 0; uint16(i) < nb_node; i++ {
		fmt.Printf("élément %v : %v\n", i, string(response.Body[33+64*i:33+64*i+32]))
	}
	//fmt.Printf("Body rep get datum : \n%v\n",string(response.Body))

	//est ce qu'on ne voudrait pas jch.jpeg? si si
	fileName := string(response.Body[33+64*3-64 : 33+64*3-32])
	//fileName := "jch.jpeg"
	//fmt.Printf("File name len: \n%d\n",len(fileName))
	fileName = strings.Trim(fileName, string(0))

	giveMeData.Body = response.Body[33+64*3-32 : 33+64*3] //jch.jpeg est aussi en 3 eme position
	fmt.Printf("\ngiveMeData : \n%v \n", giveMeData)
	MessageSender(connP2P, giveMeData)
	response = MessageListener(connP2P)
	TypeChecker(response, 131)
	fmt.Printf("Body rep get datum : \n%v\n", response.Body)

	out := make([]byte, 0)
	collectDataFile(response, connP2P, &out)

	//fmt.Printf("test recup bigFile : \n%v\n",out)

	f, errr := os.OpenFile(fileName, os.O_CREATE|os.O_RDWR, 0755) //Pk elle veut pas un string en paramètre elle...
	if errr != nil {
		fmt.Printf("Err open\n")
		log.Fatal(err)
	}

	_, err = f.Write(out)
	if err != nil {
		fmt.Printf("Err write\n")
		log.Fatal(err)
	}

	f.Close()
	//##########################################################################################################################################################################
}

//##########################################################################################################################################################################
