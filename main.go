package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

func getSecret() string {
	secret := os.Getenv("WEBHOOK_SECRET")
	if secret == "" {
		return "my_webhook_secret"
	}
	return secret
}

func verifySignature(payload []byte, signatureHeader string, secret string) bool {
	if !strings.HasPrefix(signatureHeader, "sha256=") {
		return false
	}
	signature := strings.TrimPrefix(signatureHeader, "sha256=")
	sigBytes, err := hex.DecodeString(signature)
	if err != nil {
		return false
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	expectedMAC := mac.Sum(nil)

	return hmac.Equal(sigBytes, expectedMAC)
}

func webhookHandler(w http.ResponseWriter, r *http.Request) {
	// Read the raw body bytes
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}

	// Restore the body for downstream consumers
	r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	// Get the signature header
	signatureHeader := r.Header.Get("X-Hub-Signature-256")
	if signatureHeader == "" {
		http.Error(w, "Missing signature header", http.StatusUnauthorized)
		return
	}

	// Verify signature
	secret := getSecret()
	if !verifySignature(bodyBytes, signatureHeader, secret) {
		http.Error(w, "Invalid signature", http.StatusUnauthorized)
		return
	}

	// Verify that subsequent handlers can still read the body
	restoredBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read restored body", http.StatusInternalServerError)
		return
	}

	fmt.Printf("Successfully verified payload: %s\n", string(restoredBytes))
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func main() {
	http.HandleFunc("/webhook", webhookHandler)
	fmt.Println("Starting server on :8080...")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		fmt.Printf("Server failed: %s\n", err)
	}
}
