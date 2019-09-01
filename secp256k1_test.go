package secp256k1_test

import (
	"fmt"
	"testing"
	"time"

	secp256k1 "github.com/ureeves/jwt-go-secp256k1"

	"github.com/dgrijalva/jwt-go"
	"github.com/ethereum/go-ethereum/crypto"
)

const TESTKEY = "f503f5eb94ff210c2d155e9d1c72545fe08f30baf5cd3dfbc1eb623d7bf946c6"

func TestVerification(t *testing.T) {

	key, err := crypto.HexToECDSA(TESTKEY)
	if err != nil {
		t.Fatalf("failed parsing key: %s", err)
	}

	_, err = jwt.Parse("eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NkstUiJ9.eyJpYXQiOjE1NjczNjgxMzEsImV4cCI6MzMxMjQ5NjgxMzEsInBlcm1pc3Npb25zIjpbIm5vdGlmaWNhdGlvbnMiXSwiY2FsbGJhY2siOiIvY2FsbGJhY2siLCJ0eXBlIjoic2hhcmVSZXEiLCJpc3MiOiJkaWQ6ZXRocjoweDEzZWQ4OGQ3NDRmQ2QwMGE1RDJlQTlhYzUwQjMwMjdGMkE1NENDYzIifQ.yPT8Q2YeWNnwiAcRkFzwKo53FWREYeW4HGuPw4gVBJlY61iRetokOXJMNFrDsP5rGGutaWn3-Z3QwRRvHLeu6wA", func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*secp256k1.SigningMethodSecp256K1); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		return &key.PublicKey, nil
	})

	if err != nil {
		t.Errorf("failed parsing: %s", err)
	}

	_, err = jwt.Parse("eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpYXQiOjE1NjczNjgxMzEsImF1ZCI6ImRpZDp1cG9ydDoyb3NuZko0V3k3TEJBbTJuUEJYaXJlMVdmUW43NVJyVjZUcyIsImlzcyI6ImRpZDp1cG9ydDoyb3NuZko0V3k3TEJBbTJuUEJYaXJlMVdmUW43NVJyVjZUcyJ9.Rlx4R2UOhg7UupIbZ-yf1bnf7jesTLXVq6jvEJC2LixEHl3gpgyYDGon_id-HPcg6wXF9dFtf8c1cbNPkeuaWQ", func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*secp256k1.SigningMethodSecp256K1); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		return &key.PublicKey, nil
	})

	if err != nil {
		t.Errorf("failed parsing: %s", err)
	}
}

func TestGeneration(t *testing.T) {

	key, err := crypto.HexToECDSA(TESTKEY)
	if err != nil {
		t.Fatalf("failed parsing key: %s", err)
	}

	token := jwt.NewWithClaims(secp256k1.SigningMethodES256K1, jwt.StandardClaims{
		IssuedAt: time.Now().Unix(),
	})

	_, err = token.SignedString(key)
	if err != nil {
		t.Fatalf("failed signing token: %s", err)
	}

	token = jwt.NewWithClaims(secp256k1.SigningMethodES256K1R, jwt.StandardClaims{
		IssuedAt: time.Now().Unix(),
	})

	_, err = token.SignedString(key)
	if err != nil {
		t.Fatalf("failed signing token: %s", err)
	}
}
