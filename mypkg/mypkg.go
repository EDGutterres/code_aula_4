package mypkg

import (
	"net/http"
	"os"
	"strings"

	"github.com/dgrijalva/jwt-go"
)

var jwtKey = []byte(os.Getenv("JWT_KEY"))

// Claims dd
type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

// Auth a
func Auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := strings.Split(r.Header.Get("Authorization"), " ")

		if len(authHeader) < 2 {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("Forbidden"))
			return
		}

		tknStr := authHeader[1]
		claims := &Claims{}

		tkn, _ := jwt.ParseWithClaims(tknStr, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

		if !tkn.Valid {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("Forbidden"))
			return
		}

		next.ServeHTTP(w, r)
	})
}
