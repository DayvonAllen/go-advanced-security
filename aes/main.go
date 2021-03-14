package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"log"

	"golang.org/x/crypto/bcrypt"
)

func main() {
	msg := "this is a test message"
	fakePassword := "password"

	// encrypt and then get 16 bits for the aes enDecode key
	b, err := bcrypt.GenerateFromPassword([]byte(fakePassword), bcrypt.MinCost)
	if err != nil {
		panic("Error")
	}

	genKey := b[:16]

	// encrypt
	result, err := enDecode(genKey, msg)
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Println(string(result))

	//decrypt
	result2, err := enDecode(genKey, string(result))
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Println(string(result2))
}

func enDecode(key []byte, input string) ([]byte, error) {
	// cipher gives you back a block
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("Error: %w", err)
	}
	// not secure to use the same key for both, just for the example(key needs to be 16 bits, 24 bits or 32 bits)
	// salt is the second param
	// returns a stream
	stream := cipher.NewCTR(b, key)

	buff := &bytes.Buffer{}

	steamWriter := cipher.StreamWriter{
		S: stream,
		W: buff,
	}

	// as it writes to the buffer it simultaneously encrypts the data
	_, err = steamWriter.Write([]byte(input))
	if err != nil {
		return nil, fmt.Errorf("Error: %w", err)
	}

	return buff.Bytes(), nil

}
