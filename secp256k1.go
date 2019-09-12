// Package secp256k1 implements a jwt.SigningMethod for secp256k1 signatures.
//
// Two different algorithms are implemented: ES256K and ES256K-R. The former
// produces and verifies using signatures in the R || S format, and the latter
// in R || S || V. V is the recovery byte, making it possible to recover public
// keys from signatures.
package secp256k1

import (
	"crypto"
	"crypto/ecdsa"
	"errors"
	"math/big"

	"github.com/dgrijalva/jwt-go"
	ecrypto "github.com/ethereum/go-ethereum/crypto"
)

// ES256K and ES256K-R algorithms. uPort uses SigningMethodES256KR.
var (
	// SigningMethodES256K produces and accepts 256-bit signatures using the
	// secp256k1 curve.
	// The signature is in R || S format.
	SigningMethodES256K *SigningMethodSecp256k1
	// SigningMethodES256KR produces and accepts 264-bit signatures using the
	// secp256k1 curve.
	// The signature is in R || S || V format, with V being the recovery byte.
	SigningMethodES256KR *SigningMethodSecp256k1
)

// SigningMethodSecp256k1 is the implementation of jwt.SigningMethod.
type SigningMethodSecp256k1 struct {
	alg      string
	hash     crypto.Hash
	toOutSig toOutSig
	sigLen   int
}

// encodes a produced signature to the correct output - either in R || S or
// R || S || V format.
type toOutSig func(sig []byte) []byte

func init() {
	SigningMethodES256K = &SigningMethodSecp256k1{
		alg:      "ES256K",
		hash:     crypto.SHA256,
		toOutSig: toES256K, // R || S
		sigLen:   64,
	}
	jwt.RegisterSigningMethod(SigningMethodES256K.Alg(), func() jwt.SigningMethod {
		return SigningMethodES256K
	})

	SigningMethodES256KR = &SigningMethodSecp256k1{
		alg:      "ES256K-R",
		hash:     crypto.SHA256,
		toOutSig: toES256KR, // R || S || V
		sigLen:   65,
	}
	jwt.RegisterSigningMethod(SigningMethodES256KR.Alg(), func() jwt.SigningMethod {
		return SigningMethodES256KR
	})
}

// Errors returned on different problems.
var (
	ErrWrongKeyFormat  = errors.New("wrong key type")
	ErrBadSignature    = errors.New("bad signature")
	ErrVerification    = errors.New("signature verification failed")
	ErrFailedSigning   = errors.New("failed generating signature")
	ErrHashUnavailable = errors.New("hasher unavailable")
)

// Verify verifies a secp256k1 signature in a JWT. The type of key has to be
// *ecdsa.PublicKey.
//
// Verify it is a secp256k1 key before passing, otherwise it will validate with
// that type of key instead. This can be done using ethereum's crypto package.
func (sm *SigningMethodSecp256k1) Verify(signingString, signature string, key interface{}) error {
	pub, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return ErrWrongKeyFormat
	}

	if !sm.hash.Available() {
		return ErrHashUnavailable
	}
	hasher := sm.hash.New()
	hasher.Write([]byte(signingString))

	sig, err := jwt.DecodeSegment(signature)
	if err != nil {
		return err
	}
	if len(sig) != sm.sigLen {
		return ErrBadSignature
	}

	bir := new(big.Int).SetBytes(sig[:32])   // R
	bis := new(big.Int).SetBytes(sig[32:64]) // S

	if !ecdsa.Verify(pub, hasher.Sum(nil), bir, bis) {
		return ErrVerification
	}

	return nil
}

// Sign produces a secp256k1 signature for a JWT. The type of key has
// to be *PrivateKey.
func (sm *SigningMethodSecp256k1) Sign(signingString string, key interface{}) (string, error) {
	prv, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return "", ErrWrongKeyFormat
	}

	if !sm.hash.Available() {
		return "", ErrHashUnavailable
	}
	hasher := sm.hash.New()
	hasher.Write([]byte(signingString))

	sig, err := ecrypto.Sign(hasher.Sum(nil), prv)
	if err != nil {
		return "", ErrFailedSigning
	}
	out := sm.toOutSig(sig)

	return jwt.EncodeSegment(out), nil
}

// Alg returns the algorithm name.
func (sm *SigningMethodSecp256k1) Alg() string {
	return sm.alg
}

func toES256K(sig []byte) []byte {
	return sig[:64]
}

func toES256KR(sig []byte) []byte {
	return sig[:65]
}
