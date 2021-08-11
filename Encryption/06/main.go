// authenticating with HMAC
// HMAC values in a cookie
package main

import (
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
)

const (
	key = "secret"
)

// ensure cookie is not tampered with
func getJWT(msg string) (string, error) {
	type myClaims struct {
		Email string
		jwt.StandardClaims
	}

	// create a new claim
	claims := myClaims{
		StandardClaims: jwt.StandardClaims{
			// expires in 5 minutes from now
			ExpiresAt: time.Now().Add(5 * time.Minute).Unix(),
		},
		Email: msg,
	}

	// create a token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, &claims)

	// sign the token
	ss, err := token.SignedString(key)
	if err != nil {
		return "", fmt.Errorf("error getting signed string from token")
	}

	return ss, nil
}

func main() {

	http.HandleFunc("/", home)
	http.HandleFunc("/submit", submit)

	http.ListenAndServe(":8088", nil)
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
	}

	// save email in cookie
	// "hash / message digest / digest / hash value" | "data being stored"
	c := http.Cookie{
		Name: "session",
		// Value: code + "|" + email,
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

	isEqual := true

	message := "Not logged in"
	if isEqual {
		message = "Logged in"
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
