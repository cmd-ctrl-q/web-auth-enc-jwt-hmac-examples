package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"

	"golang.org/x/crypto/bcrypt"
)

// https://www.thepolyglotdeveloper.com/2018/02/encrypt-decrypt-data-golang-application-crypto-packages/

func encryptPassword(pass string) ([]byte, error) {
	bs, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	// return first 16 bytes
	return bs, nil
}

func comparePassAndHash(hashedPass, password []byte) (bool, error) {
	err := bcrypt.CompareHashAndPassword(hashedPass, password)
	if err != nil {
		return false, fmt.Errorf("error comparing hashed text and password: %w", err)
	}

	return true, nil
}

// user password encrypts data
func encrypt(data []byte, key string) ([]byte, error) {
	// pass, err := encryptPassword(password)
	// if err != nil {
	// 	return nil, fmt.Errorf("error encrypting password: %w", err)
	// }

	// create cipher block
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return nil, fmt.Errorf("error creating cipher block: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("error wrapping block in GCM: %w", err)
	}

	// nonce is the salt,
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("error randomizing the nonce byte: %w", err)
	}

	// encrypt data
	// Note: the nonce used for encryption must be the same one used for decryption.
	// Store encryption nonce alongside decryption data if it is doing into a db, as shown below.
	cipherData := gcm.Seal(nonce, nonce, data, nil)

	return cipherData, nil
}

// user password encrypts data
func decrypt(data []byte, key string) ([]byte, error) {
	// pass, err := encryptPassword(password)
	// if err != nil {
	// 	return nil, fmt.Errorf("error encrypting password: %w", err)
	// }

	// create cipher block
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return nil, fmt.Errorf("error creating cipher block: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("error wrapping block in GCM: %w", err)
	}

	// nonce is the salt,
	nonceSize := gcm.NonceSize()
	// the nonce is the part of the data byte from start to nonceSize
	// data is everything after the nonceSize
	nonce, cipherData := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, cipherData, nil)
	if err != nil {
		return nil, fmt.Errorf("error decyrpting data with nonce: %w", err)
	}

	return plaintext, nil
}

func main() {
	data := []byte("my secret message")

	// encrypt data using password
	bs, err := encrypt(data, "password12356789")
	if err != nil {
		panic(err)
	}

	fmt.Println(string(bs))

	// decrypt data using password
	// notice: the encrypted var bs is used as the data.
	bs, err = decrypt(bs, "password12356789")
	if err != nil {
		panic(err)
	}

	fmt.Println(string(bs))

	// encrypt password
	password := "password123"

	encPass1, _ := encryptPassword(password)
	isSame, _ := comparePassAndHash(encPass1, []byte(password))

	fmt.Println("encPass1: ", encPass1)
	fmt.Println("encPass1 === password?", isSame)

	encPass2, _ := encryptPassword(password)
	isSame, _ = comparePassAndHash(encPass2, []byte(password))

	fmt.Println("encPass2: ", encPass2)
	fmt.Println("encPass2 === password?", isSame)
}
