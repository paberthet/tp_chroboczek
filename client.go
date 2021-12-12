package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"fmt"
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
	Sign   []byte
}

var serveurUrl = "jch.irif.fr:8082"
var jchPeersAddr = "https://jch.irif.fr:8082/peers/"
var jchRootAddr = "https://jch.irif.fr:8082/peers/jch.irif.fr/root"
var jchAddr = "https://jch.irif.fr:8082/peers/jch.irif.fr/addresses"

var Id = []byte{byte(0x4), byte(0x8), byte(0xf), byte(0x10)}

func newID() []byte {
	new_id := make([]byte, 4)
	_, err := rand.Read(new_id)
	if err != nil {
		fmt.Println("error new Id:", err)
		return Id
	}
	return new_id
}

//================================================================================
//						UDP Message
//================================================================================

func UDPInit(url string) *net.UDPConn {
	raddr, _ := net.ResolveUDPAddr("udp", url)
	conn, errD := net.DialUDP("udp", nil, raddr)
	if errD != nil {
		log.Printf("Connection error %v\n", errD)
		return nil
	}
	return conn
}

func NewMessage(I []byte, T []byte, B []byte, privK *ecdsa.PrivateKey) Message {
	Longueur := make([]byte, 2)
	sig := make([]byte, 0, 64)
	signature := make([]byte, 0)
	if len(I) != 4 {
		log.Fatal("Invalid Id length on message initialisation")
	}
	if len(T) != 1 {
		log.Fatal("Invalid Type length on message initialisation")
	}
	binary.BigEndian.PutUint16(Longueur[0:], uint16(len(B)))
	if privK != nil {
		data := append(I, T...)
		data = append(data, Longueur...)
		data = append(data, B...)
		sign := sha256.Sum256(data)
		r, s, err := ecdsa.Sign(rand.Reader, privK, sign[:])
		if err != nil {
			log.Fatal("Error while signing message")
		}
		sig1 := r.FillBytes(sig[:32])
		sig2 := s.FillBytes(sig[32:64])
		signature = append(signature, sig1...)
		signature = append(signature, sig2...)
	}
	mess := Message{I, T, Longueur, B, signature}
	return mess
}

func MessageToBytes(mess Message) []byte {
	ret := append(mess.Id, mess.Type...)
	ret = append(ret, mess.Length...)
	ret = append(ret, mess.Body...)
	ret = append(ret, mess.Sign...)
	return ret
}

func BytesToMessage(tab []byte, pubK *ecdsa.PublicKey) Message {
	signature := make([]byte, 0, 64)
	var r, s big.Int
	length := binary.BigEndian.Uint16(tab[5:7])
	if pubK != nil {
		if len(tab) != int(length)+7+64 {
			log.Fatal("Message is not of appropriate length for signed message")
		}
		data := sha256.Sum256(tab[:length+7])
		signature = tab[length+7:]
		r.SetBytes(signature[:32])
		s.SetBytes(signature[32:64])
		ok := ecdsa.Verify(pubK, data[:], &r, &s)
		if !ok {
			log.Fatal("Invalid signature")
		}
	}
	mess := NewMessage(tab[:4], tab[4:5], tab[7:length+7], nil)
	return mess
}

// génère message d'erreur à partir d'un message erroné
func ErrorMessageSender(mess Message, str string, conn *net.UDPConn, privK *ecdsa.PrivateKey) {
	mess.Type[0] = byte(254)
	tmp := []byte(str)
	mess.Body = tmp
	mess = NewMessage(mess.Id, mess.Type, mess.Body, privK)
	MessageSender(conn, mess)
	Id = newID() //Actualisation de Id
}

func TypeChecker(mess Message, typ int16) bool {
	typB := make([]byte, 1)
	typB[0] = byte(typ)
	if !bytes.Equal(mess.Type, typB) {
		log.Printf("Unvalid type : expected %v, got %v\n", typB, mess.Type)
		if mess.Type[0] == 254 {
			log.Printf("%v\n", string(mess.Body))
		}
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

func MessageListener(conn *net.UDPConn, sended Message, repeat bool, pubK *ecdsa.PublicKey) Message {
	messB := make([]byte, 1064)
	err := conn.SetReadDeadline(time.Now().Add(2000 * time.Millisecond))
	if err != nil {
		log.Fatalf("Timeout Set error %d\n", err)
	}
	var i int = 0
	var j int = 0

	//attente exponentielle d'une réponse
	var errRead error
	for j < 5 {
		var delay int = 2
		for i < 5 {
			_, errRead = conn.Read(messB)
			if errRead != nil {
				err = conn.SetReadDeadline(time.Now().Add(time.Duration(delay) * 200 * time.Millisecond))
				if err != nil {
					log.Fatalf("Timeout Set error %d\n", err)
				}
				delay *= 2
				i++
			} else {
				//fmt.Printf("\n\n%v\n\n", messB)
				break
			}
		}
		if errRead == nil {
			break
		}
		if !repeat { //si on decide de ne pas répéter la requette on s'arrête là
			break
		}
		if i == 5 {
			MessageSender(conn, sended)
		} else {
			break
		}
		j++
	}
	if errRead != nil { //Si on à la fin on a toujours pas réussi à écouter un message
		messB[4] = byte(254)
		rep := []byte("Pas de réponse")
		binary.BigEndian.PutUint16(messB[5:7], uint16(len(rep)))
		errMess := NewMessage(messB[:4], messB[4:5], rep, nil)
		return errMess
	}
	//on va tronquer messB car on risque des pbs de diff entre la longueur de messB (1024) et la longueur réelle du message
	mess := BytesToMessage(messB, pubK)
	return mess
}

func NATTravMessage(peeraddr [][]byte, connJCH *net.UDPConn, privK *ecdsa.PrivateKey, bobK *ecdsa.PublicKey) *net.UDPConn {
	//Préparation du message à envoyer au serveur
	T := make([]byte, 1)
	I := make([]byte, 4)
	T[0] = byte(133)
	B := make([]byte, 18)
	mess := NewMessage(I, T, B, privK)
	//Fin de préparation du message à envoyer au serveur

	//préparation en amont du message Hello,
	ext := make([]byte, 4)
	name := "panic"
	hello := append(ext, []byte(name)...)

	Type := make([]byte, 1)
	Type[0] = 0
	helloMess := NewMessage(Id, Type, hello, privK)
	//Fin préparation du Hello

	checker := false
	cmptr := 0

	for !checker && (cmptr < len(peeraddr)) {
		addr, _ := net.ResolveUDPAddr("udp", string(peeraddr[cmptr]))
		fmt.Printf("len : %v addr : %v addr bytes : %v\n", len(addr.IP), addr.IP, []byte(addr.IP))
		test_port := make([]byte, 2)
		binary.BigEndian.PutUint16(test_port[0:], uint16(addr.Port))
		fmt.Printf("port : %v port bytes %v\n", addr.Port, test_port)

		ip := append([]byte(addr.IP), test_port...)
		mess.Body = ip

		fmt.Printf("Message construit : %v\n\n", mess)

		//Envoie de la requette de traversée de NAT au serveur
		MessageSender(connJCH, mess) //Envoyé à jch obiligatoirement

		//Attente que la demande soit transmise au client par le serveur
		time.Sleep(1 * time.Second)
		//Envoi d'un Hello au client
		//Initialisation de la connexion avec le client
		connP2P, errD := net.DialUDP("udp", nil, addr)
		if errD == nil {

			//Envoi du Hello
			MessageSender(connP2P, helloMess)
			Id_tmp_client1 := helloMess.Id

			//Ecoute si Hello du client
			rep := MessageListener(connP2P, helloMess, false, bobK)
			//si on a un retour
			if (rep.Type[0] == 0) && !(bytes.Equal(rep.Id[:4], make([]byte, 4))) { //Message hello et Id non nul
				rep.Type[0] = 128 //type de hello reply, on utilise rep car il y a deja le bon id dedans
				rep = NewMessage(rep.Id, rep.Type, rep.Body, privK)
				MessageSender(connP2P, rep) //On envoie un hello reply au hello qu'on vient de recevoir
				//on peut aussi écouter le helloReply qu'on est censés recevoir en retour de notre hello
				rep = MessageListener(connP2P, rep, true, nil)
				//fmt.Printf("HelloReply mess normalement : %v\n", rep)
				if !bytes.Equal(rep.Id[:4], Id_tmp_client1) {
					fmt.Printf("Erreur : Helloreply avec le mauvais Id\n")
				}

				//à ce moment là le NAT est traversé, on peut dialoguer directement avec le client, je pense qu'il faudrait faire un return connP2P
				return connP2P
			}

			//et sinon, si on n'a pas réussi les étapes précédentes, on passe à l'adresse suivante.
		} else {
			connP2P.Close()
		}
		cmptr++
	}
	return nil
}

func checkHash(mess Message) bool {
	check := sha256.Sum256(mess.Body[32:])
	return bytes.Equal(check[:], mess.Body[:32])
}

func collectDataFile(mess Message, conn *net.UDPConn, privK *ecdsa.PrivateKey, bobK *ecdsa.PublicKey, out *[]byte) { //c'est en fait un deep first search
	if !TypeChecker(mess, 131) { //Il faut que ce soit un message Datum
		ErrorMessageSender(mess, "Bad type\n", conn, privK)
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
			Id = newID()
			giveMeData := NewMessage(Id, Type, mess.Body[33+32*i:33+32*(i+1)], privK)

			nb_try := 0
			MessageSender(conn, giveMeData)
			response := MessageListener(conn, giveMeData, true, bobK)
			for !checkHash(response) && (nb_try < 10) {
				log.Printf("Bad hash")
				MessageSender(conn, giveMeData)
				response = MessageListener(conn, giveMeData, true, bobK)

			}
			collectDataFile(response, conn, privK, bobK, out)
		}
		return
	} else { //dataType = 0 on est donc dans un chunk
		*out = append(*out, mess.Body[33:]...)
		return
	}

}
func collectDirectory(mess Message, conn *net.UDPConn, fileName string, filePath string, privK *ecdsa.PrivateKey, bobK *ecdsa.PublicKey) {
	if mess.Body[32] != 2 {
		//On est sur un File ou big file
		out := make([]byte, 0)
		collectDataFile(mess, conn, privK, bobK, &out)
		//Création du fichier dans lequel on va écrire les données
		f, errr := os.OpenFile(filePath, os.O_CREATE|os.O_RDWR, 0755) //Création du fichier dans lequel on va écrire les données
		if errr != nil {
			fmt.Printf("Err open\n")
			log.Fatal(errr)
		}
		//écriture dans le fichier
		_, errr = f.Write(out)
		if errr != nil {
			fmt.Printf("Err write\n")
			log.Fatal(errr)
		}

		f.Close()
		return
	} else {
		//Création du répertoire avec le nom fileName
		err := os.MkdirAll(filePath, 0755)
		if err != nil {
			log.Printf("Erreur création de dossier")
		}
		nb_nodes := (binary.BigEndian.Uint16(mess.Length) - 33) / 64
		for i := 0; i < int(nb_nodes); i++ {
			//Faire getdatum
			Type := make([]byte, 1)
			Type[0] = 3 //getDatum
			Length := make([]byte, 2)
			binary.BigEndian.PutUint16(Length[0:], uint16(32)) //Lenght = 32

			giveMeData := NewMessage(Id, Type, mess.Body[33+64*(i+1)-32:33+64*(i+1)], privK) //On met le bon hash dedans
			new_fileName := string(mess.Body[33+64*i : 33+64*i+32])
			new_fileName = strings.Trim(new_fileName, string(0))

			new_filePath := filePath + "/" + new_fileName

			MessageSender(conn, giveMeData)
			Id = newID()
			response := MessageListener(conn, giveMeData, true, bobK)
			if !checkHash(response) {
				log.Printf("Bad hash")
				return
			}
			collectDirectory(response, conn, new_fileName, new_filePath, privK, bobK)
		}
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
	if len(ids) > 0 {
		last := len(ids) - 1
		if len(ids[last]) == 0 {
			ids = ids[:last]
		}
	}

	return ids
}

func PeerSelector(ids [][]byte, client http.Client) ([][]byte, string, string) {
	for i, id := range ids {
		fmt.Printf("%v %v: %v\n", i, "peers", string(id))
	}
	fmt.Printf("\n\nQuel pair voulez vous contacter?\nEntrez le numéro du pair\n")
	var j int
	fmt.Scanf("%d", &j)
	peerAddr := jchPeersAddr + string(ids[j])
	addr := peerAddr + "/addresses"

	fmt.Printf("Vous allez contacter %v\n", string(ids[j]))

	reponse, err := HttpRequest("GET", addr, client)
	if err != nil {
		log.Fatalf("Error get peers addresses: %v\n", err)
	}
	reponse2 := ParseREST(reponse)
	return reponse2, peerAddr, string(ids[j])
}

//===================================================================================================
//                                SUBROUTINES
//===================================================================================================

func HelloRepeater(conn *net.UDPConn, ourPrivKey *ecdsa.PrivateKey, bobK *ecdsa.PublicKey) {
	ext := make([]byte, 4)
	name := "panic"
	hello := append(ext, []byte(name)...)

	Type := make([]byte, 1)
	Type[0] = 0
	Length := make([]byte, 2)
	binary.BigEndian.PutUint16(Length[0:], uint16(len(hello)))

	for {
		Id = newID()
		helloMess := NewMessage(Id, Type, hello, ourPrivKey)
		MessageSender(conn, helloMess)
		response := MessageListener(conn, helloMess, true, bobK)

		if !TypeChecker(response, 128) {
			ErrorMessageSender(response, "Bad type\n", conn, ourPrivKey)
		}
		if !bytes.Equal(response.Id[:4], helloMess.Id[:4]) {
			log.Printf("HelloReply avec mauvais ID\n")
		}
		time.Sleep(30 * time.Second)
	}
}

func dataReceiver(client http.Client, privateKey *ecdsa.PrivateKey, bobK *ecdsa.PublicKey, pubK []byte) {
	//Tout ce qui suit sera fait en boucle
	for {
		//Récup des pairs REST
		body, err := HttpRequest("GET", jchPeersAddr, client)
		if err != nil {
			log.Printf("Error get peers : %v\n", err)
			continue
		} else {
			//Affichage pairs et choix du pair scanf et récupération des adresses ip du pair sélectionné
			fmt.Printf("\n\n\n\n\n\n\n\n")
			peertable := ParseREST(body)

			peertableAddr, peerURL, peerName := PeerSelector(peertable, client)

			hashEmptyRoot := make([]byte, 32)
			binary.BigEndian.PutUint64(hashEmptyRoot[0:8], uint64(0xe3b0c44298fc1c14))
			binary.BigEndian.PutUint64(hashEmptyRoot[8:16], uint64(0x9afbf4c8996fb924))
			binary.BigEndian.PutUint64(hashEmptyRoot[16:24], uint64(0x27ae41e4649b934c))
			binary.BigEndian.PutUint64(hashEmptyRoot[24:32], uint64(0xa495991b7852b856))

			//création du hellomessage

			ext := make([]byte, 4)
			name := "panic"
			hello := append(ext, []byte(name)...)

			Type := make([]byte, 1)
			Type[0] = 0
			Length := make([]byte, 2)
			binary.BigEndian.PutUint16(Length[0:], uint16(len(hello)))

			//Tentative de co à l'une des adresses du pair (UDP)
			var connP2P *net.UDPConn
			var connected bool = false
			for _, addr := range peertableAddr {
				Id = newID()

				helloMess := NewMessage(Id, Type, hello, privateKey)

				connP2P = UDPInit(string(addr))
				if connP2P == nil { //Si l'établissement de la connexion a échoué, on abandonne et on passe à l'adresse suivante
					continue
				}

				MessageSender(connP2P, helloMess)                           //Il faut d'abord dire bonjour, sinon pas content
				response := MessageListener(connP2P, helloMess, true, bobK) //Helloreply
				if !TypeChecker(response, 128) || !bytes.Equal(helloMess.Id[:4], response.Id[:4]) {
					log.Printf("Tentative de connexion échouée, au stade Hello\n")
					connP2P.Close()

				} else {
					//pubKey
					response = MessageListener(connP2P, helloMess, false, bobK)
					if !TypeChecker(response, 1) {
						log.Printf("Tentative de connexion échouée, au stade pubkey\n")
						connP2P.Close()
					} else {
						fmt.Printf("Pubkey : %v\n", response.Body)
						//Pubkeyreply
						//pubKey, _ := projetcrypto.ECDHGen()
						Type := make([]byte, 1)
						Type[0] = byte(129)
						//B := make([]byte, 0) //potentiel pubK pour passer en mode non signé
						response = NewMessage(response.Id, Type, pubK, privateKey)

						MessageSender(connP2P, response)

						//Root / rootreply , il faut le faire aussi entre pairs
						response = MessageListener(connP2P, response, false, bobK)
						if !TypeChecker(response, 2) {
							log.Printf("Tentative de connexion échouée, au stade root\n")
							connP2P.Close()
						} else {
							T := make([]byte, 1)
							T[0] = byte(130)
							response = NewMessage(response.Id, T, hashEmptyRoot, privateKey)
							MessageSender(connP2P, response)
							connected = true
							break //Si on a réussi toutes ces étapes on peut arrếter d'essayer toutes les adresses
						}
					}
				}
			}
			defer connP2P.Close()
			if connected { //On ne réalise la suite que si l'on a réussi à se connecter
				//récupération root du pair
				rootURL := peerURL + "/root"
				body, err = HttpRequest("GET", rootURL, client)
				if err != nil {
					log.Fatalf("Error get root : %v\n", err)
					continue
				}

				hash := body //hash contient le hash de root pour l'instant
				fileName := "root"
				filePath := "/root"

				nodeType := byte(2) //directory

				//Préparation des messages get datum
				Type[0] = 3                                        //getDatum
				binary.BigEndian.PutUint16(Length[0:], uint16(32)) //Lenght = 32
				var response Message
				collected_directory := 0
				Id = newID()
				giveMeData := NewMessage(Id, Type, hash, privateKey)

				for nodeType == 2 { //Tant que l'on est dans un répertoire, on affiche son contenu à l'utilisateur
					fmt.Printf("\n\nVous êtes dans %v\n\n", filePath)

					MessageSender(connP2P, giveMeData)                          //On envoie la requette
					response = MessageListener(connP2P, giveMeData, true, bobK) //On recoit la réponse

					if !TypeChecker(response, 131) { //Vérification que c'est bien un datum
						log.Printf("No datum..\n")
						return
					}

					if !checkHash(response) {
						log.Printf("Bad hash in response")
						return
					}
					nodeType = response.Body[32]
					if nodeType == 2 {
						nb_node := (binary.BigEndian.Uint16(response.Length) - 33) / 64
						for i := 0; uint16(i) < nb_node; i++ {
							fmt.Printf("élément %v : %v\n", i, string(response.Body[33+64*i:33+64*i+32]))
						}
						fmt.Printf("\nPour descendre dans l'arborescence, entrez le numéro correspondant (entre %d et %d)\n", 0, nb_node-1)
						fmt.Printf("Pour télécharger le dossier complet, entrez %d\n", nb_node)
						var k int = int(nb_node) + 1
						fmt.Scanf("%d", &k)
						for k > int(nb_node) {
							fmt.Printf("Entrez un nombre entre 0 et %d\n", nb_node)
							fmt.Scanf("%d", &k)
						}
						if k != int(nb_node) {
							Id = newID()
							giveMeData = NewMessage(Id, Type, response.Body[33+64*(k+1)-32:33+64*(k+1)], privateKey) //On met à jour le hash de la donnée que l'on veut récupérer
							//On va garder en mémoire le nom du fichier/dossier vers lequel on se dirige, de cette manière on pourra nommer le fichier correctment dans notre machine
							fileName = string(response.Body[33+64*(k+1)-64 : 33+64*(k+1)-32])
							fileName = strings.Trim(fileName, string(0))
							filePath = filePath + "/" + fileName
						} else {
							//On télécharge tout le dossier
							collectDirectory(response, connP2P, fileName, "./"+"downlaod_from_"+peerName+"/"+fileName, privateKey, bobK)
							collected_directory = 1
							break //Et on arrête la descente dans l'arborescence
						}

					}
				}
				if collected_directory != 1 {
					//Sortie de la boucle, donc si nous n'avon spas télécharger un dossier complet, nous somme dans un BigFile ou un file
					out := make([]byte, 0)
					collectDataFile(response, connP2P, privateKey, bobK, &out)

					//Création du fichier dans lequel on va écrire les données
					err := os.MkdirAll("./"+"downlaod_from_"+peerName, 0755)
					if err != nil {
						log.Printf("Erreur création de dossier")
					}
					f, errr := os.OpenFile("./"+"downlaod_from_"+peerName+"/"+fileName, os.O_CREATE|os.O_RDWR, 0755) //Création du fichier dans lequel on va écrire les données
					if errr != nil {
						fmt.Printf("Err open\n")
						log.Fatal(err)
					}
					//écriture dans le fichier
					_, err = f.Write(out)
					if err != nil {
						fmt.Printf("Err write\n")
						log.Fatal(err)
					}

					f.Close()
				}
			} else {
				log.Printf("Toutes les adresses ont été testées, impossible de se connecter\n")
			}
		}
	}
}

//==================================================================================================
func main() {

	//=============================================================================================
	// Generation de notre signature
	//=============================================================================================

	//pubK, privK := projetcrypto.ECDHGen()
	privK, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	publicKey := privK.PublicKey
	pubK := make([]byte, 64)
	publicKey.X.FillBytes(pubK[:32])
	publicKey.Y.FillBytes(pubK[32:])

	var bobK *ecdsa.PublicKey
	bobK = nil

	var wg sync.WaitGroup

	//Préparation des requettes REST
	transport := http.DefaultTransport.(*http.Transport)
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	client := &http.Client{
		Transport: transport,
		Timeout:   50 * time.Second,
	}

	hashEmptyRoot := make([]byte, 32)
	//var hashEmptyRootStr string = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	//c'est sale de le faire à la main mais c'est pour le test
	binary.BigEndian.PutUint64(hashEmptyRoot[0:8], uint64(0xe3b0c44298fc1c14))
	binary.BigEndian.PutUint64(hashEmptyRoot[8:16], uint64(0x9afbf4c8996fb924))
	binary.BigEndian.PutUint64(hashEmptyRoot[16:24], uint64(0x27ae41e4649b934c))
	binary.BigEndian.PutUint64(hashEmptyRoot[24:32], uint64(0xa495991b7852b856))

	//Enregistrement auprès du serveur
	ext := make([]byte, 4)
	name := "panic"
	hello := append(ext, []byte(name)...)

	Type := make([]byte, 1)
	Type[0] = 0

	helloMess := NewMessage(newID(), Type, hello, privK)

	conn := UDPInit(serveurUrl)
	if conn == nil {
		log.Fatalf("Impossible de s'enregistrer sur serveur\n")
	}
	defer conn.Close()

	MessageSender(conn, helloMess)
	response := MessageListener(conn, helloMess, true, bobK)

	if !TypeChecker(response, 128) {
		ErrorMessageSender(response, "Bad type\n", conn, privK)
	}
	if !bytes.Equal(helloMess.Id[:4], response.Id[:4]) {
		ErrorMessageSender(response, "Bad Id\n", conn, privK)
	}

	//Publickey + PublicKeyReply

	response = MessageListener(conn, helloMess, false, bobK)
	if !TypeChecker(response, 1) {
		ErrorMessageSender(response, "Bad type\n", conn, privK)
	}
	response.Type[0] = byte(129)
	response = NewMessage(response.Id, response.Type, pubK, privK)
	MessageSender(conn, response)

	//root + rootReply

	response = MessageListener(conn, response, false, bobK)
	if !TypeChecker(response, 2) {
		ErrorMessageSender(response, "Bad type\n", conn, privK)
	}
	response.Type[0] = byte(130)
	response = NewMessage(response.Id, response.Type, hashEmptyRoot, privK)
	MessageSender(conn, response)

	wg.Add(1)
	go HelloRepeater(conn, privK, bobK)
	defer wg.Done()

	wg.Add(1)
	go dataReceiver(*client, privK, bobK, pubK)
	defer wg.Done()
	wg.Wait()
}

//##########################################################################################################################################################################
