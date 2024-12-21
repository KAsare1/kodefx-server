package utils

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strconv"

	"github.com/golang-jwt/jwt/v4"
)

// Key type for context values
type contextKey string

// Define context keys
const UserIDKey contextKey = "userID"
var jwtSecretKey = []byte(os.Getenv("JWT_SECRET"))

// Middleware to verify JWT and set userID in context
func AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        // Get token from Authorization header
        authHeader := r.Header.Get("Authorization")
        if authHeader == "" {
            http.Error(w, "Authorization header required", http.StatusUnauthorized)
            return
        }

        // Remove "Bearer " prefix if present
        tokenString := authHeader
        if len(authHeader) > 7 && authHeader[:7] == "Bearer " {
            tokenString = authHeader[7:]
        }

        // Parse and validate token
        token, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
            // Validate signing method
            if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
                return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
            }
            return jwtSecretKey, nil
        })

        if err != nil {
            http.Error(w, "Invalid token", http.StatusUnauthorized)
            return
        }

        // Extract claims
        if claims, ok := token.Claims.(*jwt.RegisteredClaims); ok && token.Valid {
            // Convert subject (user ID) to uint
            userID, err := strconv.ParseUint(claims.Subject, 10, 64)
            if err != nil {
                http.Error(w, "Invalid user ID in token", http.StatusUnauthorized)
                return
            }

            // Create new context with user ID
            ctx := context.WithValue(r.Context(), UserIDKey, uint(userID))
            
            // Call next handler with new context
            next.ServeHTTP(w, r.WithContext(ctx))
        } else {
            http.Error(w, "Invalid token claims", http.StatusUnauthorized)
            return
        }
    }
}

// Helper function to get userID from context
func GetUserIDFromContext(ctx context.Context) (uint, error) {
    userID, ok := ctx.Value(UserIDKey).(uint)
    if !ok {
        return 0, fmt.Errorf("user ID not found in context")
    }
    return userID, nil
}