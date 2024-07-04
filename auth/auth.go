package auth

import (
    "context"
    "net/http"
    "strings"

    "github.com/dgrijalva/jwt-go"
    "banking-app/handlers"
)

func VerifyToken(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        tokenString := r.Header.Get("Authorization")
        if tokenString == "" {
            http.Error(w, "Authorization token required", http.StatusUnauthorized)
            return
        }

        tokenString = strings.TrimPrefix(tokenString, "Bearer ")
        if tokenString == "" {
            http.Error(w, "Authorization token required", http.StatusUnauthorized)
            return
        }

        claims := &handlers.Claims{}
        token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
            return handlers.JwtKey, nil
        })
        if err != nil {
            if err == jwt.ErrSignatureInvalid {
                http.Error(w, "Invalid token signature", http.StatusUnauthorized)
                return
            }
            http.Error(w, "Invalid token", http.StatusUnauthorized)
            return
        }
        if !token.Valid {
            http.Error(w, "Invalid token", http.StatusUnauthorized)
            return
        }

        ctx := context.WithValue(r.Context(), "email", claims.Email)
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}
