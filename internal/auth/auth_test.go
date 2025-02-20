package auth

import (
	"testing"
)

// TestHashAndCheckPassword tests both HashPassword and CheckPasswordHash functions. 
func TestHashAndCheckPassword(t *testing.T) {
	// Define a sample password
	password := "securepassword123"

	// Step 1: Hash the password and handle errors
	hashedPassword, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword() failed: %v", err)
	}

	// Step 2: Check if the hashed password matches the original password
	if err := CheckPasswordHash(password, hashedPassword); err != nil {
		t.Fatalf("CheckPasswordHash() failed: %v", err)
	}

	// Step 3: Check incorrect password handling
	incorrectPassword := "wrongpassword"
	if err := CheckPasswordHash(incorrectPassword, hashedPassword); err == nil {
		t.Fatalf("CheckPasswordHash() did not fail for incorrect password")
	}
}