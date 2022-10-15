package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/golang-jwt/jwt/v4"
	"io"
	"log"
	"os"
)

func getPublicAndPrivateKey() (pubKey *rsa.PublicKey, priKey *rsa.PrivateKey, err error) {
	var (
		file      *os.File
		readBytes []byte
		pub       any
		ok        bool
	)

	file, err = os.Open("ssl_key/rsa_private_key.pem")
	if err != nil {
		return nil, nil, err
	}
	readBytes, err = io.ReadAll(file)
	if err != nil {
		return nil, nil, err
	}
	block, _ := pem.Decode(readBytes)
	if priKey, err = x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
		return nil, nil, err
	}

	file, err = os.Open("ssl_key/rsa_public_key.pem")
	if err != nil {
		return nil, nil, err
	}
	readBytes, err = io.ReadAll(file)
	if err != nil {
		return nil, nil, err
	}
	block, _ = pem.Decode(readBytes)
	if pub, err = x509.ParsePKIXPublicKey(block.Bytes); err != nil {
		return nil, nil, err
	}
	if pubKey, ok = pub.(*rsa.PublicKey); !ok {
		log.Fatal("No available public key")
	}

	return
}

func main() {
	signningString := "this is the sample secret"
	var (
		priKey    *rsa.PrivateKey
		pubKey    *rsa.PublicKey
		err       error
		signature string
	)

	// load the pubKey and priKey
	if pubKey, priKey, err = getPublicAndPrivateKey(); err != nil {
		log.Fatal(err.Error())
	}

	// 1. sign and verify a string
	fmt.Println(jwt.SigningMethodRS256.Alg())
	// Sign and get the complete encoded token as a string using the secret
	if signature, err = jwt.SigningMethodRS256.Sign(signningString, priKey); err != nil {
		log.Fatal(err.Error())
	}

	fmt.Println("signature", signature)

	if err = jwt.SigningMethodRS256.Verify(signningString, signature, pubKey); err != nil {
		log.Fatal(err.Error())
	}

	fmt.Println("Success")

	//// 2. sign and verify a JWT
	//token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
	//	"foo": "bar",
	//	"nbf": time.Date(2015, 10, 10, 12, 0, 0, 0, time.UTC).Unix(),
	//})
}
