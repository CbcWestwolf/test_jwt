package main

import (
	"crypto/rsa"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

var (
	publicKeyPath  = "ssl_key/rsa_public_key.pem"
	privateKeyPath = "ssl_key/rsa_private_key.pem"
	priKey         *rsa.PrivateKey
	pubKey         *rsa.PublicKey
)

func init() {
	var err error
	// load the pubKey and priKey
	if pubKey, priKey, err = getPublicAndPrivateKey(); err != nil {
		log.Fatal(err.Error())
	}
}

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

func main() {
	signningString := "this is the sample secret"
	var (
		err         error
		signature   string
		tokenString string
	)

	// 1. sign and verify a string
	// Sign and get the complete encoded token as a string using the secret
	if signature, err = jwt.SigningMethodRS256.Sign(signningString, priKey); err != nil {
		log.Fatal(err.Error())
	}
	if err = jwt.SigningMethodRS256.Verify(signningString, signature, pubKey); err != nil {
		log.Fatal("Verify", err.Error())
	}

	// 2. sign and verify a JWT
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"foo": "bar",
		"nbf": time.Date(2015, 10, 10, 12, 0, 0, 0, time.UTC).Unix(),
	})
	if tokenString, err = token.SignedString(priKey); err != nil {
		log.Fatal("SignedString", err.Error())
	}
	if token.Valid {
		log.Fatal("Should be invalid")
	}
	token, err = jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		// TODO: validate the token.Header and token.Claims here
		return pubKey, nil
	})
	if !token.Valid {
		log.Fatal("Should be valid")
	}
	parts := strings.SplitN(tokenString, ".", 3)
	// The 3rd part (signature) should not be passed into the signingString
	if err = jwt.SigningMethodRS256.Verify(strings.Join(parts[:2], "."), token.Signature, pubKey); err != nil {
		log.Fatal("Verify", err.Error())
	}

	fmt.Println("Success")
}
