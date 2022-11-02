package main

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	jwaRepo "github.com/lestrrat-go/jwx/v2/jwa"
	jwkRepo "github.com/lestrrat-go/jwx/v2/jwk"
	jwsRepo "github.com/lestrrat-go/jwx/v2/jws"
	jwtRepo "github.com/lestrrat-go/jwx/v2/jwt"
)

var (
	publicKeyPath  = "ssl_key/rsa_public_key.pem"
	privateKeyPath = "ssl_key/rsa_private_key.pem"
	keyID          = "the-key-id-0"
	issuer         = "issuer-a"
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
		ok        bool
	)

	file, err = os.Open(privateKeyPath)
	if err != nil {
		return nil, nil, err
	}
	readBytes, err = io.ReadAll(file)
	if err != nil {
		return nil, nil, err
	}
	if v, rest, err := jwkRepo.DecodePEM(readBytes); err != nil {
		log.Println(err.Error())
		log.Fatal("Error in decode private key")
	} else if len(rest) > 0 {
		log.Fatal("Rest in decode private key")
	} else if priKey, ok = v.(*rsa.PrivateKey); !ok {
		log.Fatal("Wrong type of private key")
	}

	file, err = os.Open(publicKeyPath)
	if err != nil {
		return nil, nil, err
	}
	readBytes, err = io.ReadAll(file)
	if err != nil {
		return nil, nil, err
	}
	if v, rest, err := jwkRepo.DecodePEM(readBytes); err != nil {
		log.Println(err.Error())
		log.Fatal("Error in decode public key")
	} else if len(rest) > 0 {
		log.Fatal("Rest in decode public key")
	} else if pubKey, ok = v.(*rsa.PublicKey); !ok {
		log.Fatal("Wrong type of public key")
	}

	return
}

// mainGenerateJWTandJWKS generates and prints generated JWT (as a string) and JWKS (as a json)
func main() {
	var (
		err                        error
		key                        jwkRepo.Key
		rawJSON, signedTokenString []byte

		iat   = time.Now().Unix()
		exp   = time.Date(2032, 12, 30, 6, 6, 6, 6, time.UTC).Unix()
		email = "user@pingcap.com"
	)

	// 1. generate and sign JWT
	jwt := jwtRepo.New()
	claims := []struct {
		name  string
		value interface{}
	}{
		{jwtRepo.SubjectKey, email},
		{"email", email},
		{jwtRepo.IssuedAtKey, iat},
		{jwtRepo.ExpirationKey, exp},
		{jwtRepo.IssuerKey, issuer},
	}
	for _, claim := range claims {
		if err = jwt.Set(claim.name, claim.value); err != nil {
			log.Println(claim.name, claim.value)
			log.Fatal("Error when set claim")
		}
	}
	header := jwsRepo.NewHeaders()
	headers := []struct {
		name  string
		value interface{}
	}{
		{jwsRepo.AlgorithmKey, jwaRepo.RS256},
		{jwsRepo.TypeKey, "JWT"},
		{jwsRepo.KeyIDKey, keyID},
	}
	for _, h := range headers {
		if err = header.Set(h.name, h.value); err != nil {
			log.Println(h.name, h.value)
			log.Fatal("Error when set header")
		}
	}
	if signedTokenString, err = jwtRepo.Sign(jwt, jwtRepo.WithKey(jwaRepo.RS256, priKey, jwsRepo.WithProtectedHeaders(header))); err != nil {
		log.Println(err)
		log.Fatal("Error when sign")
	} else {
		fmt.Println(string(signedTokenString))
	}

	// 2. generate JWKS from pubKey

	if key, err = jwkRepo.FromRaw(pubKey); err != nil {
		log.Fatal("Error when generate key")
	}
	// These attributes are needed for verification
	keyAttributes := []struct {
		name  string
		value interface{}
	}{
		{jwkRepo.AlgorithmKey, jwaRepo.RS256},
		{jwkRepo.KeyIDKey, keyID},
		{jwkRepo.KeyUsageKey, "sig"},
	}
	for _, t := range keyAttributes {
		if err = key.Set(t.name, t.value); err != nil {
			log.Println(err)
			log.Fatalf("Error when set %s", t.name)
		}
	}
	jwks := jwkRepo.NewSet()
	if err := jwks.AddKey(key); err != nil {
		log.Fatal("Error when jwks.AddKey")
	}
	if rawJSON, err = json.MarshalIndent(jwks, "", "  "); err != nil {
		log.Fatal("Error when marshaler json")
	}
	fmt.Println(string(rawJSON))

	// 3. verify the JWT using the JWKS
	if verifiedPayload, err := jwsRepo.Verify(signedTokenString, jwsRepo.WithKeySet(jwks)); err != nil {
		log.Println(err.Error())
		log.Fatal("Error when verify")
	} else {
		fmt.Println(string(verifiedPayload))
	}
}

// CheckJWT checks the JWT using the JWKS from local files
func CheckJWT() {
	var (
		rawJWT      []byte
		err         error
		tokenString string
		jwks        jwkRepo.Set
	)

	// 1. get jwt
	if rawJWT, err = os.ReadFile("ssl_key/JWT.txt"); err != nil {
		log.Fatal("Error when open jwt file")
	}
	tokenString = string(rawJWT)

	// 2. load jwks
	if jwks, err = jwkRepo.ReadFile("ssl_key/JWKS.json"); err != nil {
		log.Fatal("Error when load jwks file")
	}

	// 3. verify signature
	if verifiedPayload, err := jwsRepo.Verify(([]byte)(tokenString), jwsRepo.WithKeySet(jwks)); err != nil {
		log.Println(err.Error())
		log.Fatal("Error when verify")
	} else {
		fmt.Println(string(verifiedPayload))
		jwt := jwtRepo.New()
		err = jwt.(json.Unmarshaler).UnmarshalJSON(verifiedPayload)
		if err != nil {
			log.Println(err.Error())
			log.Fatal("Error when UnmarshalJSON")
		}
		if m, err := jwt.AsMap(context.Background()); err != nil {
			log.Println(err.Error())
			log.Fatal("Error when AsMap")
		} else {
			for k, v := range m {
				fmt.Println(k, v)
			}
		}
	}

	// 4. get jwt whois signature is wrong
	if rawJWT, err = os.ReadFile("ssl_key/wrongJWT.txt"); err != nil {
		log.Fatal("Error when open jwt file")
	}
	tokenString = string(rawJWT)

	// 5. fail to verify signature
	if _, err := jwsRepo.Verify(([]byte)(tokenString), jwsRepo.WithKeySet(jwks)); err != nil {
		log.Println(err.Error())
	}
}
