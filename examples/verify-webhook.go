// Verifies Attesso webhook deliveries against the shared vectors file.
//
// Usage: go run verify-webhook.go [verify-webhook-vectors.json]
//
// Exit 0 when every vector behaves as its expect_valid says; exit 1
// otherwise. The recomputation is the whole recipe: check the timestamp is
// inside the window, then recompute HMAC-SHA256 over `t + "." + body` with
// the endpoint signing secret and compare against the header's v1 value.
// Never verify a re-serialized body: sign and verify the exact bytes.
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
)

type vector struct {
	Name          string `json:"name"`
	SecretHex     string `json:"secret_hex"`
	Header        string `json:"header"`
	Body          string `json:"body"`
	Now           int64  `json:"now"`
	WindowSeconds int64  `json:"window_seconds"`
	ExpectValid   bool   `json:"expect_valid"`
}

func verifyDelivery(vector vector) (bool, string) {
	parts := strings.Split(vector.Header, ",")
	if len(parts) != 2 || !strings.HasPrefix(parts[0], "t=") || !strings.HasPrefix(parts[1], "v1=") {
		return false, "malformed_header"
	}
	// Strict shapes: canonical base-10 seconds and exactly 64 hex characters
	// (the JS sibling enforces the same); ParseInt alone would accept a
	// leading sign the header format never carries.
	digits := strings.TrimPrefix(parts[0], "t=")
	if digits == "" {
		return false, "malformed_header"
	}
	for _, digit := range digits {
		if digit < '0' || digit > '9' {
			return false, "malformed_header"
		}
	}
	timestamp, err := strconv.ParseInt(digits, 10, 64)
	if err != nil {
		return false, "malformed_header"
	}
	if difference := vector.Now - timestamp; difference > vector.WindowSeconds || -difference > vector.WindowSeconds {
		return false, "timestamp_out_of_window"
	}
	secret, err := hex.DecodeString(vector.SecretHex)
	if err != nil {
		return false, "malformed_secret"
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(strconv.FormatInt(timestamp, 10)))
	mac.Write([]byte("."))
	mac.Write([]byte(vector.Body))
	provided, err := hex.DecodeString(strings.TrimPrefix(parts[1], "v1="))
	if err != nil {
		return false, "malformed_signature"
	}
	if !hmac.Equal(provided, mac.Sum(nil)) {
		return false, "signature_mismatch"
	}
	return true, "ok"
}

func main() {
	path := "verify-webhook-vectors.json"
	if len(os.Args) > 1 {
		path = os.Args[1]
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read vectors: %v\n", err)
		os.Exit(2)
	}
	var document struct {
		Vectors []vector `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		fmt.Fprintf(os.Stderr, "parse vectors: %v\n", err)
		os.Exit(2)
	}
	failed := 0
	for _, item := range document.Vectors {
		valid, reason := verifyDelivery(item)
		conforming := valid == item.ExpectValid
		status := "PASS"
		if !conforming {
			status = "FAIL"
			failed++
		}
		fmt.Printf("%-4s %-24s valid=%v expected=%v (%s)\n", status, item.Name, valid, item.ExpectValid, reason)
	}
	if failed > 0 {
		fmt.Printf("%d vector(s) misbehaved\n", failed)
		os.Exit(1)
	}
	fmt.Println("all vectors behaved as expected")
}
