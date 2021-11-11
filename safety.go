package main

import (
	"crypto/elliptic"
	//"crypto/aes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/rand"
	"math/big"
	"fmt"
	//"errors"
)

func KeyTo64(publicKey ecdsa.PublicKey) []byte {
	formatted := make([]byte, 64)
	publicKey.X.FillBytes(formatted[:32])
	publicKey.Y.FillBytes(formatted[32:])
	return formatted
}

func MakeSign64(privateKey ecdsa.PrivateKey) ([]byte, error) {
	var r, s big.Int
	message := []byte("Ceci est une signature test ecdsa de Marc et P-Aug\n")
	hashed := sha256.Sum256(message)
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hashed[:])
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	return signature, err
}

func _64ToKey(data []byte) ecdsa.PublicKey {
	var x, y big.Int
	x.SetBytes(data[:32])
	y.SetBytes(data[32:])
	toCheckKey := ecdsa.PublicKey {
		Curve : elliptic.P256(),
		X : &x,
		Y : &y,
	}
	return toCheckKey
}

func VerifSign64(signature []byte, toCheckKey ecdsa.PublicKey) bool {
	var r, s big.Int
	r.SetBytes(signature[:32])
	s.SetBytes(signature[32:])
	message := []byte("Ceci est une signature test ecdsa de Marc et P-Aug\n")
	hashed := sha256.Sum256(message)
	ok := ecdsa.Verif(toCheckKey, hashed[:], &r, &s)
	return ok
}

func main(){

	privateKey, _ := GenerateKey(elliptic.P256(), rand.Reader)
	publicKey = privateKey.Public()

	tabKey := KeyTo64(publicKey)
	fmt.Println("%s", tabKey)

	signature, _ := MakeSign64(privateKey)
	
	ok := VerifSign64(signature, publicKey)
	if ok == true {
		fmt.Println("Well done!")
	} else {
		fmt.Println("You rebel scums!")
	}
}
