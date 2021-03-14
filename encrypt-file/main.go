package main

import (
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"os"
)

func main() {
	file, err := os.Open("test.txt")
	if err != nil {
		log.Fatalln(err)
	}

	defer file.Close()

	h := sha256.New()

	_, err = io.Copy(h, file)
	if err != nil {
		log.Fatalln(err)
	}

	xb := h.Sum(nil)

	fmt.Println(string(xb))
	fmt.Printf("%X\n", xb)
}
