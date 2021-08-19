package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log"
	"strings"
)

// HMAC - Symmetric (2-way) signing method, which uses the hashing algorithm SHA.

func main() {

	// CREATING TOKEN
	token, err := createToken("12345", []byte("secret-key"))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("hex token: ", token)

	token, err = createToken2("12345", []byte("secret-key"))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("base64 token: ", token)

	// PARSING TOKEN
	parsedToken, err := parseToken(token, "secret-key")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("parsed token: ", parsedToken)
}

// createToken will return a (hex_value|sid) or (signature|sid)
// rather than return a hex of the signed mac, could return a base64
// sid = session id
func createToken(sid string, key []byte) (string, error) {
	mac := hmac.New(sha256.New, key)
	_, err := mac.Write([]byte(sid))
	if err != nil {
		return "", fmt.Errorf("error writing sid to hash: %w", err)
	}

	signedMAC := fmt.Sprintf("%x", mac.Sum(nil))

	return signedMAC + "|" + sid, nil
}

func createToken2(sid string, key []byte) (string, error) {
	mac := hmac.New(sha256.New, key)
	_, err := mac.Write([]byte(sid))
	if err != nil {
		return "", fmt.Errorf("error writing sid to hash: %w", err)
	}

	signedMAC := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	return signedMAC + "|" + sid, nil
}

func parseToken(signedString, key string) (string, error) {
	// SplitN splits into at most 2 items
	xs := strings.SplitN(signedString, "|", 2)
	if len(xs) < 2 {
		// session id was not piped to the signature. signature|sid
		return "", fmt.Errorf("error session id was not piped to the singuature")
	}

	b64 := xs[0]
	// the decoded but signed string is the signed session id (sid) or mac1
	decoded, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", fmt.Errorf("cannot decode base 64 to string: %w", err)
	}

	mac := hmac.New(sha256.New, []byte(key))
	// must use the original session id "12345" which is in xs[1] to write to the mac
	_, err = mac.Write([]byte(xs[1]))
	if err != nil {
		return "", fmt.Errorf("error writing sid to hash: %w", err)
	}

	// verify the signature matches the session id
	// Equal(mac1, mac2), ie. Equal(signed, unsigned)
	equals := hmac.Equal(decoded, mac.Sum(nil))
	if !equals {
		return "", fmt.Errorf("error signed and unsigned macs do not equal")
	}

	return xs[1], nil
}
