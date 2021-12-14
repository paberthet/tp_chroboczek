//package projetcrypto
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"math/big"
)

//cette fonction convertit une clef publique ecdsa en chaine d octets
func PubKeyToByte(pub ecdsa.PublicKey) []byte {
	x := pub.X.Bytes()
	x = x[:32]
	y := pub.Y.Bytes()
	y = y[:32]
	ret := append(x, y...)
	return ret
	//ici on considère que la courbe est le standard P256
}

//cette fonction convertit une chaine d octet en clef publique ecdsa
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

//genere une clef publique ecdsa au format chaine d octets et son secret
func ECDHGen() ([]byte, ecdsa.PrivateKey) {
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Printf("Error initializing private key ECDH")
	}
	public := private.PublicKey
	B := PubKeyToByte(public)
	return B, *private
}

//genere un secret partage a partir d une chaine d octets et d une clef privee ecdsa
func ECDHSharedGen(data []byte, privat ecdsa.PrivateKey) []byte {
	pub := ByteToPubKey(data)
	shared, _ := pub.Curve.ScalarMult(pub.X, pub.Y, privat.D.Bytes())
	return shared.Bytes()
}

//chiffre un message via AES128 GCM en une chaine d octets
func AESEncrypt(dh []byte, data []byte) []byte {
	key := sha256.Sum256(dh)
	key128 := key[:16]
	c, err := aes.NewCipher(key128)
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
	return gcm.Seal(nonce, nonce, data, key[16:])
}

//dechiffre un chiffre via AES28 GCM en une chaine d octets
func AESDecrypt(dh []byte, data []byte) []byte {
	key := sha256.Sum256(dh)
	key128 := key[:16]
	c, err := aes.NewCipher(key128)
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
	plaintext, err := gcm.Open(nil, nonce, data, key[16:])
	if err != nil {
		log.Printf("Error while decrypting : %v\n", err)
	}
	return plaintext
}

func main() {
	Bobpub, Bobpriv := ECDHGen()
	AlicePub, AlicePriv := ECDHGen()

	AliceShared := ECDHSharedGen(Bobpub, AlicePriv)
	BobShared := ECDHSharedGen(AlicePub, Bobpriv)

	fmt.Printf("Clé publique d'Alice au format octet : %v\n", AlicePub)
	fmt.Printf("Clé publique de Bob au format octet : %v\n", Bobpub)

	fmt.Printf("Alice et Bob ont le même secret : %v\n", bytes.Equal(AliceShared, BobShared))

	AliceClair := "Bonjour je m'appelle Alice --- Hello my name is Alice --- Dzien dobry, ja jestem Alice"
	BobClair := "Ich heisse Bob --- me liamo Bob --- yé souis Bob"

	fmt.Printf("\n\nClair d'Alice : %v\n", AliceClair)
	fmt.Printf("Clair de Bob : %v\n", BobClair)

	AliceChiffre := AESEncrypt(AliceShared, []byte(AliceClair))
	BobChiffre := AESEncrypt(BobShared, []byte(BobClair))

	_, Charliepriv := ECDHGen()
	CharlieShared := ECDHSharedGen(AlicePub, Charliepriv)

	AliceDechiffre := string(AESDecrypt(AliceShared, BobChiffre))
	BobDechiffre := string(AESDecrypt(BobShared, AliceChiffre))
	CharlieDechiffre := string(AESDecrypt(CharlieShared, AliceChiffre))

	fmt.Printf("\n\nDéchiffré par Alice : %v\n", AliceDechiffre)
	fmt.Printf("Déchiffré par Bob : %v\n", BobDechiffre)
	fmt.Printf("Tentative de Charlie : %v\n", CharlieDechiffre)
}
