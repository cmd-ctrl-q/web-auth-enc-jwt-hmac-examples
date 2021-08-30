package main

import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/amazon"
)

var oauth = &oauth2.Config{
	ClientID:     os.Getenv("AMAZON_OAUTH_CLIENT_ID"),
	ClientSecret: os.Getenv("AMAZON_OAUTH_CLIENT_SECRET"),

	// amazon Endpoint auth returns a code which can be used
	// by the token to get a token.
	Endpoint:    amazon.Endpoint,
	RedirectURL: "http://localhost:8080/oauth/amazon/receive",
	Scopes:      []string{"profile"},
}

type user struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password []byte `json:"-"`
}

var db = map[string]user{}
var sessions = map[string]string{}    // for after login
var oauthExp = map[string]time.Time{} // key = uuid, value = expiration time

func main() {
	// check environment variables
	if oauth.ClientID == "" {
		log.Fatal("environment variables were not set")
	}

	http.HandleFunc("/", index)
	http.HandleFunc("/register", register)
	http.HandleFunc("/login", login)
	http.HandleFunc("/oauth/amazon/login", oAmazonLogin)
	// http.HandleFunc("/oauth/github/login", oGithubLogin)
	http.HandleFunc("/logout", logout)
	http.HandleFunc("/oauth/amazon/receive", oAmazonReceive)
	// http.HandleFunc("/oauth2/receive", completeGithubOauth)

	http.ListenAndServe(":8080", nil)
}

func index(w http.ResponseWriter, r *http.Request) {

	c, err := r.Cookie("sessionID")
	if err != nil {
		c = &http.Cookie{
			Name:  "sessionID",
			Value: "",
		}
	}

	sID, err := parseToken(c.Value)
	if err != nil {
		log.Println("index parseToken", err)
	}

	var e string
	if sID != "" {
		e = sessions[sID]
	}

	var u string
	if user, ok := db[e]; ok {
		u = user.Username
	}

	errMsg := r.FormValue("msg")

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
		<!-- session variables -->
		<p><strong>Username: %s</strong></p>
		<p><strong>Email: %s</strong></p>
		<p><strong>Error: %s</strong></p>

		<!-- register -->
		<form action="/register" method="post">
			<label for="username">Username</label>
			<input type="text" username="u" placeholder="Username">
			<input type="email" username="e" placeholder="Username">
			<input type="password" name="p">
			<input type="submit">
		</form>

		<!-- regular login -->
		<h3>Regular Login</h3>
		<form action="/login" method="post">
			<label for="username">Username</label>
			<input type="email" username="e" placeholder="Username">
			<input type="password" name="p">
			<input type="submit">
		</form>

		<!-- amazon oauth 2 login -->
		<h3>Login with Amazon Oauth</h3>
		<form action="/login" method="post">
			<input type="submit" value="Login with Amazon">
		</form>

		<!-- Logout --> 
		<form action="/logout" method="post">
			<input type="submit" value="logout">
		</form>
	</body>
	</html>
	`, u, e, errMsg)
}

func register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		msg := url.QueryEscape("your method was not post")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	e := r.FormValue("e")
	if e == "" {
		msg := url.QueryEscape("your email needs to not be empty")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	p := r.FormValue("p")
	if p == "" {
		msg := url.QueryEscape("your email password needs to not be empty")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	u := r.FormValue("username")
	if u == "" {
		msg := url.QueryEscape("your first name needs to not be empty")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	bsp, err := bcrypt.GenerateFromPassword([]byte(p), bcrypt.DefaultCost)
	if err != nil {
		msg := "there was an internal server error - evil laugh: hahahahaha"
		http.Error(w, msg, http.StatusInternalServerError)
		return
	}
	log.Println("password", p)
	log.Println("bcrypted", bsp)
	db[e] = user{
		Username: u,
		Password: bsp,
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		msg := url.QueryEscape("your method was not post")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	e := r.FormValue("e")
	if e == "" {
		msg := url.QueryEscape("your email needs to not be empty")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	p := r.FormValue("p")
	if p == "" {
		msg := url.QueryEscape("your email password needs to not be empty")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	if _, ok := db[e]; !ok {
		msg := url.QueryEscape("your email or password didn't match")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	err := bcrypt.CompareHashAndPassword(db[e].Password, []byte(p))
	if err != nil {
		msg := url.QueryEscape("your email or password didn't match")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	sUUID := uuid.New().String()
	sessions[sUUID] = e
	token, err := createToken(sUUID)
	if err != nil {
		log.Println("couldn't createToken in login", err)
		msg := url.QueryEscape("our server didn't get enough lunch and is not working 200% right now. Try bak later")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	c := http.Cookie{
		Name:  "sessionID",
		Value: token,
	}

	http.SetCookie(w, &c)

	msg := url.QueryEscape("you logged in " + e)
	http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
}

func logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	c, err := r.Cookie("sessionID")
	if err != nil {
		c = &http.Cookie{
			Name:  "sessionID",
			Value: "",
		}
	}

	sID, err := parseToken(c.Value)
	if err != nil {
		log.Println("index parseToken", err)
	}

	delete(sessions, sID)

	c.MaxAge = -1

	http.SetCookie(w, c)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func oAmazonLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther) // 303
		return
	}

	id := uuid.New().String()
	oauthExp[id] = time.Now().Add(time.Hour)

	// redirect to amazon endpoint to get code for user
	http.Redirect(w, r, oauth.AuthCodeURL(id), http.StatusSeeOther)
}

func oAmazonReceive(w http.ResponseWriter, r *http.Request) {
	state := r.FormValue("state")
	if state == "" {
		msg := url.QueryEscape("state was empty in oAmazonReceive")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	// we got this code from amazon
	code := r.FormValue("code")
	if code == "" {
		msg := url.QueryEscape("code was empty in oAmazonReceive")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	expT := oauthExp[state]
	if time.Now().After(expT) {
		msg := url.QueryEscape("oauth took too long time.now.after")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	// exchange our code for a token
	// this uses the client secret also
	// the TokenURL is called
	// we get back a token
	t, err := oauth.Exchange(r.Context(), code)
	if err != nil {
		msg := url.QueryEscape("couldn't do oauth exchange: " + err.Error())
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	ts := oauth.TokenSource(r.Context(), t)
	c := oauth2.NewClient(r.Context(), ts)

	resp, err := c.Get("https://api.amazon.com/user/profile")
	if err != nil {
		msg := url.QueryEscape("couldn't get at amazon: " + err.Error())
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}
	defer resp.Body.Close()

	bs, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		msg := url.QueryEscape("couldn't read resp body: " + err.Error())
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		msg := url.QueryEscape("not a 200 resp code: " + string(bs))
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	fmt.Println(string(bs))

	// fmt.Fprint(w, string(bs))
	io.WriteString(w, string(bs))
}
