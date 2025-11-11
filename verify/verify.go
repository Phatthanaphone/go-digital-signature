package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run verify.go <signature-hex>")
		return
	}

	signatureHex := os.Args[1]

	// โหลด public key จากไฟล์
	publicKey := loadPublicKey("public.pem")

	signature, err := hex.DecodeString(signatureHex)
	if err != nil {
		log.Fatalf("Error decoding signature hex: %v", err)
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

	// Calculate SHA-256 hash of JSON bytes
	hash := sha256.Sum256(documentBytes)

	// Verify signature
	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hash[:], signature)
	if err != nil {
		fmt.Println("Verification Failed ❌")
	} else {
		fmt.Println("Verification Successful ✅")
	}
}

func loadPublicKey(filename string) *rsa.PublicKey {
	publicKeyBytes, err := os.ReadFile(filename)
	if err != nil {
		log.Fatalf("Error reading public key: %v", err)
	}

	block, _ := pem.Decode(publicKeyBytes)
	if block == nil || block.Type != "PUBLIC KEY" {
		log.Fatal("Failed to decode PEM block containing public key")
	}

	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		log.Fatalf("Error parsing public key: %v", err)
	}

	publicKey, ok := key.(*rsa.PublicKey)
	if !ok {
		log.Fatal("Not an RSA public key")
	}

	return publicKey
}
