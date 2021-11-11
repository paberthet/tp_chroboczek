package main

import (
	"crypto/elliptic"
	"crypto/aes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/rand"
	"math/big"
	"fmt"
	"errors"
)

var r, s big.Int

message := []byte("Ceci est une signature ecdsa de Marc et P-Aug\n")
hashed := sha256.Sum256(message)

privateKey, err := GenerateKey(elliptic.P256(), rand.Reader)
publicKey = privateKey.Public()

func KeyTo64(publicKey crypto.PublicKey) byte[] {
	formatted := make([]byte, 64)
	publicKey.X.FillBytes(formatted[:32])
	publicKey.Y.FillBytes(formatted[32:])
	return formatted
}

func MakeSign64(privateKey crypto.PrivateKey) ([]byte, error) {
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hashed[:])
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	return signature, err
}

func 64ToKey(data []byte) crypto.PublicKey {
	var x, y big.Int
	x.SetBytes(data[:32])
	y.SetBytes(data[32:])
	toCheckKey := ecdsa.publicKey {
		Curve : elliptic.P256(),
		X : &x,
		Y : &y,
	}
	return toCheckKey
}

func VerifSign64(signature []byte) bool {
	r.SetBytes(signature[:32])
	s.SetBytes(signature[32:])
	ok = ecdsa.Verif(toCheckKey, hashed[:], &r, &s)
	return ok
}
