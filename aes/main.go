package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"io"
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

	wtr := &bytes.Buffer{}

	encWriter, err := encryptWriter(wtr, genKey)
	if err != nil {
		log.Fatalln(err)
	}

	_, err = io.WriteString(encWriter, msg)
	if err != nil {
		log.Fatalln(err)
	}

	encrypted := wtr.String()
	fmt.Println(string(encrypted))
}

func enDecode(key []byte, input string) ([]byte, error) {
	// cipher gives you back a block
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("Error: %w", err)
	}

	// iv := make([]byte, aes.BlockSize)

	// _, err = io.ReadFull(rand.Reader, iv)
	// if err != nil {
	// 	return nil, nil, fmt.Errorf(err)
	// }

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

// make a wrapper around a writer
func encryptWriter(wtr io.Writer, key []byte) (io.Writer, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("Error: %w", err)
	}

	stream := cipher.NewCTR(b, key)

	return cipher.StreamWriter{
		S: stream,
		W: wtr,
	}, nil
}
