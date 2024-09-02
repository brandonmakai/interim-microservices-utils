package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"log"
)


func Encrypt(secret string, message []byte) (string, error) {

	// Creating key here instead of redeclaring secret due to Go's type safety
	key := []byte(secret)

	// Utilizing a slice 32 here due to New Cipher requiring groups of 16, 24, or 32 bytes to create blocks
	block, err := aes.NewCipher(key[:32])
	if err != nil {
		log.Fatalf("Failed to create a cipher at %v", err)
	}

	fmt.Println(aes.BlockSize)

	ciphertext := make([]byte, aes.BlockSize+len(message))

	// Slicing ciphertext here to later fill the empty 16 byte slice with data
	// This is required as CFBEncrypter requires the block to be the same size as the iv (16 bytes)
	// iv is used to make sure the same message generates a different encryption by having the first
	// 16 bytes be randomly generated
	iv := ciphertext[:aes.BlockSize]
	fmt.Println(iv)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		log.Fatalf("Failed to fill iv with random numbers at %v", err)
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], message)

	return base64.RawStdEncoding.EncodeToString(ciphertext), nil
}

// Utilizes XOR
// Basically compares the binary of the key and the plaintext to generate ciphertext
// so to get the plaintext back you can compare the encrpyted text to the key 

func Decrypt(secret string, encrypted string) []byte {

	key := []byte(secret)
	ciphertext, err := base64.RawStdEncoding.DecodeString(encrypted)
	if err != nil {
		log.Fatalf("Failed to decode encrpyted string into bytes: %v", err)
	}

	block, _ := aes.NewCipher(key[:32])

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	return ciphertext
}