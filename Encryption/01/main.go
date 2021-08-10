/*
Encryption:

Symmetric key
- AES

Asymmetric key
- RSA
- bcrypt (uni-symmetrical)

Encrypting an email
- symmetric key - encrypt the message
	- AES

- compare sent / received
- SHA
*/
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"log"

	"golang.org/x/crypto/bcrypt"
)

func enDecode(key []byte, input string) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("couldn't new Cipher %w", err)
	}

	// initialization vetor (salt)
	iv := make([]byte, aes.BlockSize)
	_, err = io.ReadFull(rand.Reader, iv)
	if err != nil {
		return nil, fmt.Errorf("couldn't randomize iv %w", err)
	}

	s := cipher.NewCTR(block, iv)

	buff := &bytes.Buffer{}
	sw := cipher.StreamWriter{
		S: s,
		W: buff, // stream writer writes to buffer,
	}

	_, err = sw.Write([]byte(input))
	if err != nil {
		return nil, fmt.Errorf("couldn't sw.Write to streamwriter %w: ", err)
	}

	output := buff.Bytes()
	return output, nil
}

func main() {
	msg := "some message"

	password := "password123"

	bs, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		log.Fatalln(err) // fatal does not print the stack, panic does.
	}

	bs = bs[:16] // get first 16 bytes of password

	result, err := enDecode(bs, msg)
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Println("result: ", string(result))

	result, err = enDecode(bs, string(result))
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Println("result: ", string(result))

	//
	wtr := &bytes.Buffer{}
	encWriter, err := encryptWriter(wtr, bs)
}

func encryptWriter(w io.Writer, key []byte) (io.Writer, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("couldn't new Cipher %w", err)
	}

	// initialization vetor (salt)
	iv := make([]byte, aes.BlockSize)

	s := cipher.NewCTR(block, iv)

	return cipher.StreamWriter{
		S: s,
		W: w, // stream writer writes to buffer,
	}, nil
}
