package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

func HashPassword(password string) (string, error) {
	hashedBytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	return string(hashedBytes), nil
}

func CheckPasswordHash(password, hash string) error {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if err != nil {
		return err
	}
	return nil
}

func GetBearerToken(headers http.Header) (string, error) {
	authHeader, exists := headers["Authorization"]
	if !exists || len(authHeader) == 0 {
		return "", errors.New("authorization header is missing")
	}

	headerValue := authHeader[0]

	// Check if it begins with "Bearer"
	if !strings.HasPrefix(headerValue, "Bearer ") {
		return "", errors.New("authorization header is malformed")
	}

	// Remove the "Bearer " prefix and trim whitespace
	token := strings.TrimSpace(strings.TrimPrefix(headerValue, "Bearer "))
	return token, nil
}

func MakeRefreshToken() (string, error) {
	randomBytes := make([]byte, 32)
	_, err := rand.Read(randomBytes) // Use crypto/rand
	if err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err) // Wrap error
	}

	token := hex.EncodeToString(randomBytes)
	return token, nil
}

func GetAPIKey(headers http.Header) (string, error) {
	authHeader, exists := headers["Authorization"]
	if !exists || len(authHeader) == 0 {
		return "", errors.New("authorization header is missing")
	}

	headerValue := authHeader[0]

	if !strings.HasPrefix(headerValue, "ApiKey ") {
		return "", errors.New("authorization header is malformed")
	}

	apiKey := strings.TrimSpace(strings.TrimPrefix(headerValue, "ApiKey "))

	return apiKey, nil
}
