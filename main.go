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
	"github.com/golang-jwt/jwt/v4"
	jwkRepo "github.com/lestrrat-go/jwx/jwk"
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
	token.Header["kid"] = keyID
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

	// 3. verify a JWT using JWKS with kid
	jwks := keyfunc.NewGiven(map[string]keyfunc.GivenKey{
		keyID: keyfunc.NewGivenRSA(pubKey),
	})
	if token, err = jwt.Parse(tokenString, jwks.Keyfunc); err != nil {
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
		err         error
		tokenString string
		jwk         jwkRepo.Key
	)

	// 1. generate and sign JWT
	iat := time.Now().Unix()
	exp := time.Date(2032, 12, 30, 6, 6, 6, 6, time.UTC).Unix()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub":   "chenbochuan@pingcap.com",
		"email": "chenbochuan@pingcap.com",
		"iat":   iat,
		"exp":   exp,
		"iss":   issuer,
	})
	token.Header["kid"] = keyID
	if tokenString, err = token.SignedString(priKey); err != nil {
		log.Fatal("SignedString", err.Error())
	}
	if token.Valid {
		log.Fatal("Should be invalid")
	}
	fmt.Println(tokenString)

	// 2. generate JWKS from pubKey
	if jwk, err = jwkRepo.New(pubKey); err != nil {
		log.Fatal("Error when creating a jwk from pubKey")
	}
	if err = jwk.Set(jwkRepo.KeyIDKey, keyID); err != nil {
		log.Fatal("Error when setting kid")
	}
	jwks := jwkRepo.NewSet()
	if ok := jwks.Add(jwk); !ok {
		log.Fatal("jwk already exists in jwks")
	}
	if cont, err := jwks.(json.Marshaler).MarshalJSON(); err != nil {
		log.Fatal("Error when marchaler")
	} else {
		// use
		// 	echo '<jwks>' | jq .
		// to format
		fmt.Println(string(cont))
	}
}

// main checks the JWT using the JWKS from local files
func main() {
	var (
		rawJWT, rawJWKS []byte
		err             error
		tokenString     string
		jwks            *keyfunc.JWKS
		token           *jwt.Token
		publicKey       interface{}
	)

	// 1. get jwt
	if rawJWT, err = os.ReadFile("ssl_key/JWT.txt"); err != nil {
		log.Fatal("Error when open jwt file")
	}
	tokenString = string(rawJWT)

	// 2. load jwks
	if rawJWKS, err = os.ReadFile("ssl_key/JWKS.json"); err != nil {
		log.Fatal("Error when open jwks file")
	}
	if jwks, err = keyfunc.NewJSON(rawJWKS); err != nil {
		log.Fatal("Error when load jwks")
	}

	// 3. verify signature
	if token, err = jwt.Parse(tokenString, jwks.Keyfunc); err != nil {
		log.Fatal("Error when parse jwt")
	}
	if publicKey, err = jwks.Keyfunc(token); err != nil {
		log.Fatal("Error when matching jwk")
	}
	fmt.Println(token.Claims)

	// 4. get jwt whois signature is wrong
	if rawJWT, err = os.ReadFile("ssl_key/wrongJWT.txt"); err != nil {
		log.Fatal("Error when open jwt file")
	}
	tokenString = string(rawJWT)

	// 5. fail to verify signature
	if token, err = jwt.Parse(tokenString, jwks.Keyfunc); err != nil {
		log.Fatal("Error when parse the wrong jwt")
	}
	if publicKey, err = jwks.Keyfunc(token); err != nil {
		log.Fatal("Error when matching jwk")
	}
}
