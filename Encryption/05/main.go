/*

JWT is used to see if someone has tampered with the data
being sent. It is not encrypted.

Header
Payload
Signature

The signature is the HMAC SHA256 which is encrypted.
*/
package main

import (
	"fmt"
	"log"

	"github.com/dgrijalva/jwt-go"
)

// HMAC key
var signKey = []byte("your-secret-key")

type CustomClaims struct {
	Foo string `json:"foo"`
	jwt.StandardClaims
}

func main() {

	claims := CustomClaims{
		Foo: "bar",
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: 15000,
			Issuer:    "test",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	ss, err := token.SignedString(signKey)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%v", ss)

	// then pass ss as a cookie or session

}
