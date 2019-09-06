package secp256k1_test

import (
	"fmt"
	"testing"

	secp256k1 "github.com/ureeves/jwt-go-secp256k1"

	"github.com/dgrijalva/jwt-go"
	"github.com/ethereum/go-ethereum/crypto"
)

func TestVerification(t *testing.T) {

	key, err := crypto.HexToECDSA(TestKey)
	if err != nil {
		t.Fatalf("failed parsing key: %s", err)
	}

	t.Run("ES256K", func(t *testing.T) {

		for _, sString := range ES256K_Data {
			_, err = jwt.Parse(sString, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*secp256k1.SigningMethodSecp256K1); !ok {
					return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
				}

				return &key.PublicKey, nil
			})

			if err != nil {
				t.Errorf("%s: %s", sString, err)
			}
		}
	})

	t.Run("ES256K-R", func(t *testing.T) {

		for _, sString := range ES256KR_Data {
			_, err := jwt.Parse(sString, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*secp256k1.SigningMethodSecp256K1); !ok {
					return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
				}

				return &key.PublicKey, nil
			})

			if err != nil {
				t.Errorf("%s: %s", sString, err)
			}
		}
	})

}

func TestGeneration(t *testing.T) {

	key, err := crypto.HexToECDSA(TestKey)
	if err != nil {
		t.Fatalf("failed parsing key: %s", err)
	}

	for i := 0; i < 128; i++ {

		t.Run("ES256K/N="+string(i), func(t *testing.T) {
			token := jwt.NewWithClaims(secp256k1.SigningMethodES256K1, jwt.StandardClaims{
				IssuedAt: int64(i),
			})

			sString, err := token.SignedString(key)
			if err != nil {
				t.Fatalf("failed signing token: %s", err)
			}

			_, err = jwt.Parse(sString, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*secp256k1.SigningMethodSecp256K1); !ok {
					return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
				}

				return &key.PublicKey, nil
			})

			if err != nil {
				t.Fatalf("failed verifying signed token")
			}
		})

		t.Run("ES256K-R/N="+string(i), func(t *testing.T) {

			token := jwt.NewWithClaims(secp256k1.SigningMethodES256K1R, jwt.StandardClaims{
				IssuedAt: int64(i),
			})

			sString, err := token.SignedString(key)
			if err != nil {
				t.Fatalf("failed signing token: %s", err)
			}

			_, err = jwt.Parse(sString, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*secp256k1.SigningMethodSecp256K1); !ok {
					return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
				}

				return &key.PublicKey, nil
			})

			if err != nil {
				t.Fatalf("failed verifying signed token")
			}
		})
	}

}
