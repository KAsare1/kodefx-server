package utils

import (
	"context"
	"errors"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/golang-jwt/jwt/v4"
)

type contextKey string

const UserIDKey contextKey = "userID"


func GetUserIDFromContext(r *http.Request) (uint, error) {
    userID, ok := r.Context().Value(UserIDKey).(uint)
    if !ok {
        return 0, errors.New("user ID not found in context")
    }
    return userID, nil
}


func AuthMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Get token from Authorization header
        authHeader := r.Header.Get("Authorization")
        if authHeader == "" {
            http.Error(w, "Authorization header required", http.StatusUnauthorized)
            return
        }

        // Extract the token
        tokenString := strings.Replace(authHeader, "Bearer ", "", 1)

        // Parse and validate the token
        claims := &jwt.RegisteredClaims{}
        token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
            return []byte(os.Getenv("SECRET_KEY")), nil 
        })

        if err != nil || !token.Valid {
            http.Error(w, "Invalid token", http.StatusUnauthorized)
            return
        }

        userID, err := strconv.ParseUint(claims.Subject, 10, 64)
        if err != nil {
            http.Error(w, "Invalid user ID in token", http.StatusUnauthorized)
            return
        }

        ctx := context.WithValue(r.Context(), UserIDKey, uint(userID))
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}