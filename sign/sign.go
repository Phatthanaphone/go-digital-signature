package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
)

func main() {
	// Load Private Key
	privateKeyBytes, err := ioutil.ReadFile("private.pem")
	if err != nil {
		log.Fatalf("Error reading private key: %v", err)
	}

	// Decode PEM block
	block, _ := pem.Decode(privateKeyBytes)
	if block == nil {
		log.Fatal("Failed to decode PEM block containing private key")
	}

	var privateKey *rsa.PrivateKey

	if block.Type == "RSA PRIVATE KEY" {
		// PKCS#1
		privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			log.Fatalf("Error parsing PKCS#1 private key: %v", err)
		}
	} else if block.Type == "PRIVATE KEY" {
		// PKCS#8
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			log.Fatalf("Error parsing PKCS#8 private key: %v", err)
		}
		var ok bool
		privateKey, ok = key.(*rsa.PrivateKey)
		if !ok {
			log.Fatal("Key is not RSA private key")
		}
	} else {
		log.Fatalf("Unsupported key type: %s", block.Type)
	}

	// ✅ Instead of reading a file, create a map
	documentMap := map[string]interface{}{
		"client_id":    "EXAMPLE_CLIENT_ID",
		"phone_number": "999999999",
		"password":     "123456",	
	}

	// Convert map to JSON bytes
	documentBytes, err := json.Marshal(documentMap)
	if err != nil {
		log.Fatalf("Error marshaling JSON: %v", err)
	}

	// Hash the JSON
	hash := sha256.Sum256(documentBytes)

	// Sign the hash
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hash[:])
	if err != nil {
		log.Fatalf("Error signing document: %v", err)
	}

	// Convert signature to hex
	signatureHex := hex.EncodeToString(signature)

	// Output
	fmt.Println("Original JSON Document:", string(documentBytes))
	fmt.Println("Digital Signature:", signatureHex)
}
