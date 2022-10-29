package main

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"

	"github.com/MicahParks/keyfunc"
	jwtv4 "github.com/golang-jwt/jwt/v4"
	jwaRepo "github.com/lestrrat-go/jwx/v2/jwa"
	jwkRepo "github.com/lestrrat-go/jwx/v2/jwk"
	jwsRepo "github.com/lestrrat-go/jwx/v2/jws"
	jwtRepo "github.com/lestrrat-go/jwx/v2/jwt"
)

var (
	publicKeyPath  = "ssl_key/rsa_public_key.pem"
	privateKeyPath = "ssl_key/rsa_private_key.pem"
	keyID          = "the-key-id"
	issuer         = "<issuer-abc>"
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
	if priKey, err = jwtv4.ParseRSAPrivateKeyFromPEM(readBytes); err != nil {
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
	if pubKey, err = jwtv4.ParseRSAPublicKeyFromPEM(readBytes); err != nil {
		log.Println(err.Error())
		log.Fatal("Error in parsing public key")
	}

	return
}

// mainTry examines some usages
func mainTry() {
	signningString := "this is the sample secret"
	var (
		err         error
		signature   string
		tokenString string
	)

	// 1. sign and verify a string
	// Sign and get the complete encoded token as a string using the secret
	if signature, err = jwtv4.SigningMethodRS256.Sign(signningString, priKey); err != nil {
		log.Fatal(err.Error())
	}
	if err = jwtv4.SigningMethodRS256.Verify(signningString, signature, pubKey); err != nil {
		log.Fatal("Verify", err.Error())
	}

	// 2. sign and verify a JWT
	token := jwtv4.NewWithClaims(jwtv4.SigningMethodRS256, jwtv4.MapClaims{
		"foo": "bar",
		"nbf": time.Date(2015, 10, 10, 12, 0, 0, 0, time.UTC).Unix(),
	})
	token.Header["kid"] = keyID
	if tokenString, err = token.SignedString(priKey); err != nil {
		log.Fatal("SignedString", err.Error())
	}
	if token.Valid {
		log.Fatal("Should be invalid")
	}
	token, err = jwtv4.Parse(tokenString, func(token *jwtv4.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwtv4.SigningMethodRSA); !ok {
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
	if err = jwtv4.SigningMethodRS256.Verify(strings.Join(parts[:2], "."), token.Signature, pubKey); err != nil {
		log.Fatal("Verify", err.Error())
	}

	// 3. verify a JWT using JWKS with kid
	jwks := keyfunc.NewGiven(map[string]keyfunc.GivenKey{
		keyID: keyfunc.NewGivenRSA(pubKey),
	})
	if token, err = jwtv4.Parse(tokenString, jwks.Keyfunc); err != nil {
		log.Fatal("Fail to parse tokenString", tokenString)
	}
	if !token.Valid {
		log.Fatal("Should be valid")
	}
	fmt.Println(token.Header, token.Claims)

	fmt.Println("Success")
}

// mainGenerateJWTandJWKS generates and prints generated JWT (as a string) and JWKS (as a json)
func mainGenerateJWTandJWKS() {
	var (
		err     error
		key     jwkRepo.Key
		rawJSON []byte
		iat     = time.Now().Unix()
		exp     = time.Date(2032, 12, 30, 6, 6, 6, 6, time.UTC).Unix()
		email   = "chenbochuan@pingcap.com"
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
		{jwsRepo.KeyIDKey, keyID},
		{jwsRepo.TypeKey, "JWT"},
	}
	for _, h := range headers {
		if err = header.Set(h.name, h.value); err != nil {
			log.Println(h.name, h.value)
			log.Fatal("Error when set header")
		}
	}
	if signature, err := jwtRepo.Sign(jwt, jwtRepo.WithKey(jwaRepo.RS256, priKey, jwsRepo.WithProtectedHeaders(header))); err != nil {
		log.Println(err)
		log.Fatal("Error when sign")
	} else {
		fmt.Println(string(signature))
	}

	// 2. generate JWKS from pubKey

	if key, err = jwkRepo.FromRaw(pubKey); err != nil {
		log.Fatal("Error when generate key")
	}
	if err = key.Set(jwkRepo.KeyIDKey, keyID); err != nil {
		log.Println(err)
		log.Fatal("Error when set key id")
	}
	jwks := jwkRepo.NewSet()
	jwks.AddKey(key)
	if rawJSON, err = jwks.(json.Marshaler).MarshalJSON(); err != nil {
		log.Fatal("Error when marshaler json")
	}
	// use
	// 	echo '<jwks>' | jq .
	// to format
	fmt.Println(string(rawJSON))
}

// main checks the JWT using the JWKS from local files
//func TODO() {
//	var (
//		rawJWT, rawJWKS []byte
//		err             error
//		tokenString     string
//		jwks            jwkRepo.Set
//	)
//
//	// 1. get jwt
//	if rawJWT, err = os.ReadFile("ssl_key/JWT.txt"); err != nil {
//		log.Fatal("Error when open jwt file")
//	}
//	tokenString = string(rawJWT)
//	//parts := strings.SplitN(tokenString, ".", 3)
//
//	// 2. load jwks
//	if rawJWKS, err = os.ReadFile("ssl_key/JWKS.json"); err != nil {
//		log.Fatal("Error when open jwks file")
//	}
//	jwks = jwkRepo.NewSet()
//	if err = jwks.(json.Unmarshaler).UnmarshalJSON(rawJWKS); err != nil {
//		log.Fatal("Error when unmarshal jwks")
//	}
//	fmt.Println(jwks.Len())
//	if key, ok := jwks.Get(0); !ok {
//		log.Fatal("No key")
//	} else {
//		fmt.Println(key.KeyID())
//		fmt.Println(key.Algorithm())
//	}
//
//	// 3. verify signature
//	if verified, err := jwsRepo.VerifySet(([]byte)(tokenString), jwks); err != nil {
//		log.Println(err.Error())
//		log.Fatal("Error when verify")
//	} else {
//		fmt.Println(string(verified))
//	}
//
//	// 4. get jwt whois signature is wrong
//	//if rawJWT, err = os.ReadFile("ssl_key/wrongJWT.txt"); err != nil {
//	//	log.Fatal("Error when open jwt file")
//	//}
//	//tokenString = string(rawJWT)
//
//	// 5. fail to verify signature
//
//}
