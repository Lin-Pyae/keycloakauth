package middleware

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net/http"

	"github.com/golang-jwt/jwt"
	"github.com/julienschmidt/httprouter"
)

func parseKeycloakRSAPublicKey(base64Encoded string) (*rsa.PublicKey, error) {
	buf, err := base64.StdEncoding.DecodeString(base64Encoded)
	if err != nil {
		return nil, err
	}
	parsedKey, err := x509.ParsePKIXPublicKey(buf)
	if err != nil {
		return nil, err
	}
	publicKey, ok := parsedKey.(*rsa.PublicKey)
	if ok {
		return publicKey, nil
	}
	return nil, fmt.Errorf("unexpected key type %T", publicKey)
}

// Middleware function to check the presence of a custom header
func AuthMiddleware(next httprouter.Handle, base64publicKey string, allowed_users []string) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		fmt.Println("This is authentication middleware")

		publicKey, err := parseKeycloakRSAPublicKey(string(base64publicKey))
		tokenString := r.Header["Token"]

		if len(tokenString) == 0 {
			http.Error(w, "Token required", http.StatusForbidden)
			return
		}
		token, err := jwt.Parse(tokenString[0], func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return publicKey, nil
		})

		if err != nil {
			fmt.Println("Error parsing or validating token:", err)
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}

		if !token.Valid {
			fmt.Println("Invalid token")
			http.Error(w, "Invalid token", http.StatusForbidden)
			return
		}

		decryptedToken := token.Claims.(jwt.MapClaims)
		username := decryptedToken["preferred_username"]
		is_user_authenticated := false

		for _, allowed_user := range allowed_users {
			if username == allowed_user {
				is_user_authenticated = true
			}
		}
		if is_user_authenticated {
			next(w, r, ps)
		} else {
			http.Error(w, "user not allowed", http.StatusForbidden)
			return
		}

	}
}
