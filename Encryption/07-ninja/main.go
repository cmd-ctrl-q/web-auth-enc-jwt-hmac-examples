package main

import (
	"fmt"
	"log"
	"net/http"
	"net/url"

	"golang.org/x/crypto/bcrypt"
)

func main() {
	http.HandleFunc("/", home)
	http.HandleFunc("/register", register)

	http.ListenAndServe(":8081", nil)
}

var DB = map[string]string{}

func register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		errorMsg := url.QueryEscape("error wrong method")
		http.Redirect(w, r, "/?errormsg="+errorMsg, http.StatusSeeOther)
		return
	}

	// get data from form
	username := r.FormValue("username")
	password := r.FormValue("password")

	// hash password using bcrypt
	hashPass, err := encryptPassword(password)
	if err != nil {
		log.Println("error encrypting password")
		errorMsg := "there was an internal server error"
		http.Error(w, errorMsg, http.StatusInternalServerError)
		return
	}

	// store in db / map
	DB["username"] = username
	DB["password"] = string(hashPass)

	fmt.Println(DB["username"])
	fmt.Println(DB["password"])

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func home(w http.ResponseWriter, r *http.Request) {
	// get error if any from the /register route which would
	// show up in the url
	var e string
	errMsg := r.FormValue("errormsg")
	if errMsg != "" {
		e = "Error:"
	}

	// create html
	fmt.Fprintf(w, `
		<!DOCTYPE html>
		<html lang="en">
		<head>
		    <meta charset="UTF-8">
		    <meta http-equiv="X-UA-Compatible" content="IE=edge">
		    <meta name="viewport" content="width=device-width, initial-scale=1.0">
		    <title>Document</title>
		</head>
		<body>
			<small><strong>%s %s</strong></small>
			<h2>Register</h2>
			<form action="/register" method="post">
				Username: <input type="email" name="username" placeholder="username"/>
				Password: <input type="password" name="password" placeholder="password"/>
				<input type="submit" />
			</form>
		</body>
		</html>
	`, e, errMsg)

}

func encryptPassword(password string) ([]byte, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("error generating hash from password: %w", err)
	}

	return hash, nil
}
