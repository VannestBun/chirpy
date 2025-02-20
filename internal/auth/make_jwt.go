package auth

import (
    "time"
    "github.com/golang-jwt/jwt/v5"
    "github.com/google/uuid"
	"fmt"
)

func MakeJWT(userID uuid.UUID, tokenSecret string, expiresIn time.Duration) (string, error) {
    now := time.Now().UTC()
    claims := jwt.RegisteredClaims{
        Issuer:    "chirpy",
        IssuedAt:  jwt.NewNumericDate(now),
        ExpiresAt: jwt.NewNumericDate(now.Add(expiresIn)),
        Subject:   userID.String(),
    }

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	return token.SignedString([]byte(tokenSecret))
}

func ValidateJWT(tokenString, tokenSecret string) (uuid.UUID, error) {
    var claims jwt.RegisteredClaims
    
    keyFunc := func(token *jwt.Token) (interface{}, error) {
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, fmt.Errorf("unexpected signing method: %v", token.Method)
        }
        return []byte(tokenSecret), nil // The key should be the tokenSecret as bytes
    }

    token, err := jwt.ParseWithClaims(tokenString, &claims, keyFunc)
    if err != nil {
        return uuid.UUID{}, err
    }

	if !token.Valid {
        return uuid.UUID{}, fmt.Errorf("invalid token")
    }

	userID, err := uuid.Parse(claims.Subject)
    if err != nil {
        return uuid.UUID{}, err
    }

    return userID, nil

}