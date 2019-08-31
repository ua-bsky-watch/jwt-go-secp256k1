package secp256k1_test

import (
	"fmt"
	"testing"

	secp256k1 "github.com/ureeves/jwt-go-secp256k1"

	"github.com/dgrijalva/jwt-go"
	"github.com/ethereum/go-ethereum/crypto"
)

func TestSigningMethod(t *testing.T) {

	crypto.GenerateKey()

	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("failed generating key: %s", err)
	}

	// Create the Claims
	claims := &jwt.StandardClaims{
		Issuer: "test",
	}

	expectedToken := jwt.NewWithClaims(secp256k1.SigningMethodES256K1, claims)

	tokenString, err := expectedToken.SignedString(key)
	if err != nil {
		t.Fatalf("failed getting signedString: %s", err)
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*secp256k1.SigningMethod); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		return &key.PublicKey, nil
	})
	if err != nil {
		t.Fatalf("failed parsing: %s", err)
	}

	if token.Raw != tokenString {
		t.Fatalf("parse->unparse not equal tokens")
	}
}
