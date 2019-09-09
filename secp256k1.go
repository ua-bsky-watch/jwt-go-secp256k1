// Package secp256k1 implements a jwt.SigningMethod for secp256k1 signatures.
package secp256k1

import (
	"crypto"
	"crypto/ecdsa"
	"errors"
	"math/big"

	"github.com/dgrijalva/jwt-go"
	ecrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
)

var curve = secp256k1.S256()

// All the different instances of the algorithm. e.g. uport uses SigningMethodES256K1R
var (
	SigningMethodES256K1  *SigningMethodSecp256K1
	SigningMethodES256K1R *SigningMethodSecp256K1
)

// SigningMethodSecp256K1 is the implementation of jwt.SigningMethod.
type SigningMethodSecp256K1 struct {
	alg      string
	h        crypto.Hash
	toRS     toRS
	toOutSig toOutSig
}

// encodes a produced signature to the correct output - either in R || S or
// R || S || V format.
type toOutSig func(sig []byte) []byte

// checks incoming signature and return it in R || S format.
type toRS func(sig []byte) ([]byte, error)

func init() {
	SigningMethodES256K1 = &SigningMethodSecp256K1{
		alg:      "ES256K",
		h:        crypto.SHA256,
		toRS:     toRSES256K,
		toOutSig: toES256K,
	}
	jwt.RegisterSigningMethod(SigningMethodES256K1.Alg(), func() jwt.SigningMethod {
		return SigningMethodES256K1
	})

	SigningMethodES256K1R = &SigningMethodSecp256K1{
		alg:      "ES256K-R",
		h:        crypto.SHA256,
		toRS:     toRSES256KR,
		toOutSig: toES256KR,
	}
	jwt.RegisterSigningMethod(SigningMethodES256K1R.Alg(), func() jwt.SigningMethod {
		return SigningMethodES256K1R
	})
}

// Errors returned on different problems.
var (
	ErrWrongKeyFormat  = errors.New("wrong key format")
	ErrVerification    = errors.New("signature verification failed")
	ErrFailedSigning   = errors.New("failed generating signature")
	ErrHashUnavailable = errors.New("hasher unavailable")
)

// Verify verifies a secp256k1 signature given an *ecdsa.PublicKey.
func (sm *SigningMethodSecp256K1) Verify(signingString, signature string, key interface{}) error {
	pubKey, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return ErrWrongKeyFormat
	}
	pub := ecrypto.FromECDSAPub(pubKey)

	if !sm.h.Available() {
		return ErrHashUnavailable
	}
	hasher := sm.h.New()
	hasher.Write([]byte(signingString))

	sig, err := jwt.DecodeSegment(signature)
	if err != nil {
		return err
	}

	rs, err := sm.toRS(sig)
	if err != nil {
		return ErrVerification
	}

	// normalizes the signature to a "low s" form if necessary.
	x, y := curve.Unmarshal(rs)
	bi := new(big.Int)
	if bi.Neg(y).Cmp(y) > 0 {
		y = bi
	}

	if !ecrypto.VerifySignature(pub, hasher.Sum(nil), curve.Marshal(x, y)) {
		return ErrVerification
	}

	return nil
}

// Sign generates a secp256k1 signature given an *ecdsa.PrivateKey.
func (sm *SigningMethodSecp256K1) Sign(signingString string, key interface{}) (string, error) {
	prv, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return "", ErrWrongKeyFormat
	}

	if !sm.h.Available() {
		return "", ErrHashUnavailable
	}
	hasher := sm.h.New()
	hasher.Write([]byte(signingString))

	sig, err := ecrypto.Sign(hasher.Sum(nil), prv)
	if err != nil {
		return "", ErrFailedSigning
	}
	out := sm.toOutSig(sig)

	return jwt.EncodeSegment(out), nil
}

// Alg returns the algorithm name
func (sm *SigningMethodSecp256K1) Alg() string {
	return sm.alg
}

func toES256K(sig []byte) []byte {
	return sig[:64]
}

func toES256KR(sig []byte) []byte {
	return sig
}

func toRSES256K(sig []byte) ([]byte, error) {
	if len(sig) != 64 {
		return nil, ErrVerification
	}

	return sig, nil
}

func toRSES256KR(sig []byte) ([]byte, error) {
	if len(sig) != 65 {
		return nil, ErrVerification
	}

	return sig[:64], nil
}
