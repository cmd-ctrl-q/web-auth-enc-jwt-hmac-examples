/*
Base64
- not encryption


*/
package main

import (
	"encoding/base64"
	"fmt"
)

func encode(msg string) string {
	return base64.URLEncoding.EncodeToString([]byte(msg))
}

func decode(encoded string) ([]byte, error) {

	return base64.URLEncoding.DecodeString(encoded)
}

func main() {
	msg := "some amazing message"

	encodedStr := encode(msg)
	fmt.Println("Encoded:", encodedStr)

	s, _ := decode(encodedStr)
	fmt.Println("Decoded: ", string(s))

	// *** String Encoding ***
	// encode
	// encoded := base64.StdEncoding.EncodeToString([]byte(msg))
	// fmt.Println(encoded)

	// decode
	// decode, _ := base64.StdEncoding.DecodeString(encoded)
	// fmt.Println(string(decode))

	// *** URL Encoding ***
	// encoded = base64.URLEncoding.EncodeToString([]byte(msg))
	// fmt.Println(encoded)

	// decode
	// fmt.Println(string(decode))
}
