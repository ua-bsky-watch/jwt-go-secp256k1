// Package secp256k1 implements a jwt.SigningMethod for secp256k1 signatures.
package secp256k1

import (
	"crypto/ecdsa"
	"errors"

	"github.com/dgrijalva/jwt-go"
	"github.com/ethereum/go-ethereum/crypto"
)

// SigningMethodES256K1 if the instance of the jwt.SigningMethod implementation.
var SigningMethodES256K1 *SigningMethod

// SigningMethod is the implementation of jwt.SigningMethod.
type SigningMethod struct {
	alg string
}

func init() {
	SigningMethodES256K1 = &SigningMethod{
		alg: "ES256K",
	}
	jwt.RegisterSigningMethod(SigningMethodES256K1.Alg(), func() jwt.SigningMethod {
		return SigningMethodES256K1
	})
}

// Errors returned on different problems
var (
	ErrWrongKeyFormat = errors.New("wrong key format")
	ErrVerification   = errors.New("signature verification failed")
	ErrFailedSigning  = errors.New("failed generating signature")
)

// Verify verifies a secp256k1 signature given an *ecdsa.PublicKey.
func (sm *SigningMethod) Verify(signingString, signature string, key interface{}) error {
	pubKey, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return ErrWrongKeyFormat
	}
	pub := crypto.FromECDSAPub(pubKey)

	sig, err := jwt.DecodeSegment(signature)
	if err != nil {
		return err
	}

	hash := crypto.Keccak256([]byte(signingString))

	if !crypto.VerifySignature(pub, hash, sig[:64]) {
		return ErrVerification
	}

	return nil
}

// Sign generates a secp256k1 signature given an *ecdsa.PublicKey.
func (sm *SigningMethod) Sign(signingString string, key interface{}) (string, error) {
	prv, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return "", ErrWrongKeyFormat
	}

	hash := crypto.Keccak256([]byte(signingString))

	sig, err := crypto.Sign(hash, prv)
	if err != nil {
		return "", ErrFailedSigning
	}

	return jwt.EncodeSegment(sig), nil
}

// Alg returns the algorithm name
func (sm *SigningMethod) Alg() string {
	return sm.alg
}
