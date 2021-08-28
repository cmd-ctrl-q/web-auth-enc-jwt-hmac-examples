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
)

// client id: 955acae12db1c7b77f2c
// secret: fd4ad5276557697e8bd57f39d3fe0cb7346d9bea

func main() {
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
