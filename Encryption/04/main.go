// authenticating with HMAC
// HMAC values in a cookie
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
)

const (
	key = "secret"
)

// ensure cookie is not tampered with
func encryptDataWithHMAC(data string) string {
	h := hmac.New(sha256.New, []byte(key))
	// write
	_, err := h.Write([]byte(data))
	if err != nil {
		log.Println(err)
		return ""
	}
	return fmt.Sprintf("%x", h.Sum(nil))
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

	code := encryptDataWithHMAC(email)

	// save email in cookie
	// "hash / message digest / digest / hash value" | "data being stored"
	c := http.Cookie{
		Name:  "session",
		Value: code + "|" + email,
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
	// separate at most 2 blocks
	xs := strings.SplitN(c.Value, "|", 2)
	if len(xs) == 2 {
		clientCode := xs[0]
		clientEmail := xs[1]

		code := encryptDataWithHMAC(clientEmail)
		isEqual = hmac.Equal([]byte(clientCode), []byte(code))
	}

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
