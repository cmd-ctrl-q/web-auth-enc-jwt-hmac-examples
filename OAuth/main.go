/*
Oauth:
User authorizes one website to do something at another website.
- e.g. give a website access to your dropbox to store or retrieve files.
- also use oauth to login.
- it mainly just sends the general info about the user to the website.
- can also give a website to post as you.

Two most common ways to do oauth:
Inflight/client credentials
- more secure but requires server.
Implicit
- better for frontend, less secure.

Oauth1
- requries hmac signatures
Oauth2
- requires only https

Process:
- logs in with Oauth2 using e.g. google Oauth2
- redirects user to Google Oauth login page
	- user is asked to grant permissions
	- what to share from google account
- google redirects back to your website with a code.
- your site exchanges code and secret for access token to google
- your site uses token to get who the user is on google.
*/
package main

import (
	"fmt"
	"net/http"
	"os"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

var githubOauthConfig = &oauth2.Config{
	ClientID:     os.Getenv("OAUTH_CLIENT_ID"),
	ClientSecret: os.Getenv("OAUTH_CLIENT_SECRET"),
	Endpoint:     github.Endpoint,
}

func main() {
	http.HandleFunc("/", index)
	http.HandleFunc("/oauth/github", startGithubOauth)
	http.HandleFunc("/oauth/recieve", completeGithubOauth)
	http.ListenAndServe(":8080", nil)
}

func index(w http.ResponseWriter, r *http.Request) {
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
		<form action="/oauth/github" method="post">
			<input type="submit", value="Login with Github">
		</form>   
	</body>
	</html>
	`)
}

func startGithubOauth(w http.ResponseWriter, r *http.Request) {
	redirectURL := githubOauthConfig.AuthCodeURL("0000")
	http.Redirect(w, r, redirectURL, http.StatusSeeOther)
}

func completeGithubOauth(w http.ResponseWriter, r *http.Request) {
	// get params
	code := r.FormValue("code")
	state := r.FormValue("state")

	if state != "0000" {
		http.Error(w, "state is incorrect", http.StatusBadRequest)
		return
	}

	token, err := githubOauthConfig.Exchange(r.Context(), code)
	if err != nil {
		http.Error(w, "Couldn't login", http.StatusInternalServerError)
		return
	}

	// get token source
	ts := githubOauthConfig.TokenSource(r.Context(), token)

	// get http client, can now make calls to github on behalf of user
	client := oauth2.NewClient(r.Context(), ts)
}
