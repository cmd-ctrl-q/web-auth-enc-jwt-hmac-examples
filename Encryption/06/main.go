/*

The more data you have in your custom claims, the less responsiveness
it will be
*/
package main

import (
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
)

func main() {

	http.HandleFunc("/", home)
	http.HandleFunc("/submit", submit)

	http.ListenAndServe(":8088", nil)
}

const key = "secret"

type myClaims struct {
	Email string
	jwt.StandardClaims
}

// ensure cookie is not tampered with
func getJWT(msg string) (string, error) {

	// create a new claim
	claims := myClaims{
		Email: msg,
		StandardClaims: jwt.StandardClaims{
			// expires in 5 minutes from now
			ExpiresAt: time.Now().Add(5 * time.Minute).Unix(),
		},
	}

	// create token from newly created claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, &claims)

	// sign the token
	ss, err := token.SignedString([]byte(key))
	if err != nil {
		return "", fmt.Errorf("error getting signed string from token")
	}

	return ss, nil
}

func submit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	// set cookies
	email := r.FormValue("email")
	if email == "" {
		// if no email, then redirect to /
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	ss, err := getJWT(email)
	if err != nil {
		http.Error(w, "unable to get jwt", http.StatusInternalServerError)
		return
	}

	// save token string (jwt) in cookie
	c := http.Cookie{
		Name:  "session",
		Value: ss,
	}

	// set cookie
	http.SetCookie(w, &c)

	// redirect user
	http.Redirect(w, r, "/", http.StatusSeeOther)

}

func home(w http.ResponseWriter, r *http.Request) {

	c, err := r.Cookie("session")
	if err != nil {
		// create new cookie if one doesn't already exist
		c = &http.Cookie{}
	}

	ss := c.Value

	// unpack the jwt and verify it by giving it your key
	// parse jwt from client to validate/verify the token
	// the func(...) is the callback, it parses the claims
	// and checks the header but hasn't yet verified the signature.
	// until it returns []byte(key)
	token, err := jwt.ParseWithClaims(ss, &myClaims{}, func(tokenBeforeVerification *jwt.Token) (interface{}, error) {
		// check that the algorithms match
		if tokenBeforeVerification.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, fmt.Errorf("someone tried to hack, change signing method")
		}
		return []byte(key), nil
	})

	// check if token is valid, and there was no error paring token string
	// Notice: check error first else you get a dereference error.
	// Occured because the token was a nil value, but you were trying
	// to get a field from the nil token which threw error.
	// Therefore, you cannot dereference nil to get the value of Valid
	isEqual := err == nil && token.Valid

	message := "Not logged in"
	if isEqual {
		message = "Logged in!"
		// assert your claims are your custom claims 'myClaims'
		// theoretically, its not necessary to assert it is your custom type
		// because you know it is.
		claims := token.Claims.(*myClaims)
		fmt.Println("Email:", claims.Email)
		fmt.Println("Expires at (Unix):", claims.ExpiresAt)
		fmt.Println("Expires at (Date):", time.Unix(claims.ExpiresAt, 0))
	}

	html := `
		<!DOCTYPE html>
		<html lang="en">
		<head>
		    <meta charset="UTF-8">
		    <meta http-equiv="X-UA-Compatible" content="IE=edge">
		    <meta name="viewport" content="width=device-width, initial-scale=1.0">
		    <title>HMAC example</title>
		</head>
		<body>
			<h1>HMAC example</h1>
		<p>Cookie value:` + c.Value + `</p>
		<p>Message:` + message + `</p>
			<form action="/submit" method="post">
				<input type="text" name="email" /> 
				<input type="submit" />
			</form>
		</body>
		</html>
		`

	// // fmt.Fprintf(w, "Hello, world")
	io.WriteString(w, html)
}
