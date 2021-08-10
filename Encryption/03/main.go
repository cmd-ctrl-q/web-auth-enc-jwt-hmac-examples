package main

import (
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"os"
)

func main() {
	// *** encrypt a string ***
	h := sha256.New()
	h.Write([]byte("Hello, world\n"))
	fmt.Printf("%x", h.Sum(nil))

	// *** encrypt a file ***
	f, err := os.Open("file.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	// make new hash using sha256
	h = sha256.New()
	// copy source 'f' into destination 'h'
	// ie copy content (f) into h (hash)
	if _, err := io.Copy(h, f); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Type h: %T\n", h)
	xb := h.Sum(nil) // Sum returns the result
	fmt.Printf("Type xb: %T\n", xb)
	fmt.Printf("Hex xb: %x", xb)
}
