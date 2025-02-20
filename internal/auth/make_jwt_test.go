package auth

import (
	"testing"
	"github.com/google/uuid"
	"time"
)

func TestJWT(t *testing.T) {
    userID := uuid.New()
    secret := "your-test-secret"

    t.Run("valid token", func(t *testing.T) {
        // Create token with 1 hour duration
        token, err := MakeJWT(userID, secret, time.Hour)
        if err != nil {
            t.Fatalf("Failed to create token: %v", err)
        }

        // Validate token
        gotUserID, err := ValidateJWT(token, secret)
        if err != nil {
            t.Fatalf("Failed to validate token: %v", err)
        }

        // Check if we got back the same userID
        if gotUserID != userID {
            t.Errorf("Got userID %v, want %v", gotUserID, userID)
        }
    })

    t.Run("expired token", func(t *testing.T) {
        // Create token that's already expired
        token, err := MakeJWT(userID, secret, -time.Hour)
        if err != nil {
            t.Fatalf("Failed to create token: %v", err)
        }

        // Try to validate expired token
        _, err = ValidateJWT(token, secret)
        if err == nil {
            t.Error("Expected error for expired token, got nil")
        }
    })

    t.Run("wrong secret", func(t *testing.T) {
        // Create token with correct secret
        token, err := MakeJWT(userID, secret, time.Hour)
        if err != nil {
            t.Fatalf("Failed to create token: %v", err)
        }

        // Try to validate with wrong secret
        wrongSecret := "wrong-secret"
        _, err = ValidateJWT(token, wrongSecret)
        if err == nil {
            t.Error("Expected error when validating with wrong secret, got nil")
        }
    })
}