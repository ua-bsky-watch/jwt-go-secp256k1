# jwt-go-secp256k1

[![Build Status](https://img.shields.io/travis/ureeves/jwt-go-secp256k1?style=flat-square)](https://travis-ci.org/ureeves/jwt-go-secp256k1)
[![codecov](https://img.shields.io/codecov/c/github/ureeves/jwt-go-secp256k1?style=flat-square)](https://codecov.io/gh/ureeves/jwt-go-secp256k1)
[![GoDoc](https://img.shields.io/badge/godoc-reference-%235272B4?style=flat-square)](https://godoc.org/github.com/ureeves/jwt-go-secp256k1)

An implementation of a secp256k1 SignatureMethod for
github.com/dgrijalva/jwt-go.

Implements two different algorithms:

- ES256K
- ES256K-R

The latter allows for public key recovery.
