package main

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/golang-jwt/jwt/v4"
)

var (
	publicKeyPath  = "ssl_key/rsa_public_key.pem"
	privateKeyPath = "ssl_key/rsa_private_key.pem"
)

func getPublicAndPrivateKey() (pubKey *rsa.PublicKey, priKey *rsa.PrivateKey, err error) {
	var (
		file      *os.File
		readBytes []byte
	)

	file, err = os.Open(privateKeyPath)
	if err != nil {
		return nil, nil, err
	}
	readBytes, err = io.ReadAll(file)
	if err != nil {
		return nil, nil, err
	}
	if priKey, err = jwt.ParseRSAPrivateKeyFromPEM(readBytes); err != nil {
		log.Println(err.Error())
		log.Fatal("Error in parsing private key")
	}

	file, err = os.Open(publicKeyPath)
	if err != nil {
		return nil, nil, err
	}
	readBytes, err = io.ReadAll(file)
	if err != nil {
		return nil, nil, err
	}
	if pubKey, err = jwt.ParseRSAPublicKeyFromPEM(readBytes); err != nil {
		log.Println(err.Error())
		log.Fatal("Error in parsing public key")
	}

	return
}

func isTokenValid(token *jwt.Token, err error) bool {
	if token.Valid {
		return true
	} else if errors.Is(err, jwt.ErrTokenMalformed) {
		log.Print("That's not even a token")
	} else if errors.Is(err, jwt.ErrTokenExpired) || errors.Is(err, jwt.ErrTokenNotValidYet) {
		// Token is either expired or not active yet
		log.Print("Timing is everything")
	} else {
		log.Print("Couldn't handle this token:", err)
	}
	return false
}

func main() {
	signningString := "this is the sample secret"
	var (
		priKey    *rsa.PrivateKey
		pubKey    *rsa.PublicKey
		err       error
		signature string
		//jwToken   string
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
		log.Fatal("Verify", err.Error())
	}

	//// 2. sign and verify a JWT
	//token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
	//	"foo": "bar",
	//	"nbf": time.Date(2015, 10, 10, 12, 0, 0, 0, time.UTC).Unix(),
	//})
	//if jwToken, err = token.SignedString(priKey); err != nil {
	//	log.Fatal("SignedString", err.Error())
	//}
	//fmt.Println("jwToken", jwToken)
	//fmt.Println("valid", token.Valid)
	//if tempToken, err := jwt.Parse
	//if err = jwt.SigningMethodRS256.Verify(jwToken, token.Signature, pubKey); err != nil {
	//	log.Fatal("Verify", err.Error())
	//}

	fmt.Println("Success")
}
