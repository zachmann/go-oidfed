package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"log"
	"os"

	"github.com/golang-jwt/jwt"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"

	"github.com/zachmann/go-oidfed/examples/ta/config"
	"github.com/zachmann/go-oidfed/internal/jwx"
)

func genJWKS() jwk.Set {
	sk := mustNewKey()
	jwks := jwx.KeyToJWKS(sk.Public(), jwa.ES512)
	return jwks
}

func mustNewKey() *ecdsa.PrivateKey {
	sk, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	return sk
}

func mustLoadKey() crypto.Signer {
	data, err := os.ReadFile(config.Get().SigningKeyFile)
	if err != nil {
		sk := mustNewKey()
		if err = os.WriteFile(config.Get().SigningKeyFile, exportECPrivateKeyAsPem(sk), 0600); err != nil {
			log.Fatal(err)
		}
		return sk
	}
	sk, err := jwt.ParseECPrivateKeyFromPEM(data)
	if err != nil {
		log.Fatal(err)
	}
	return sk
}

var signingKey crypto.Signer
var signingJWKS jwk.Set

func initKey() {
	signingKey = mustLoadKey()

	key, err := jwk.New(signingKey.Public())
	if err != nil {
		log.Fatal(err)
	}
	if err = jwk.AssignKeyID(key); err != nil {
		log.Fatal(err)
	}
	if err = key.Set(jwk.KeyUsageKey, jwk.ForSignature); err != nil {
		log.Fatal(err)
	}
	if err = key.Set(jwk.AlgorithmKey, jwa.ES512); err != nil {
		log.Fatal(err)
	}
	signingJWKS = jwk.NewSet()
	signingJWKS.Add(key)
}

func exportECPrivateKeyAsPem(privkey *ecdsa.PrivateKey) []byte {
	privkeyBytes, _ := x509.MarshalECPrivateKey(privkey)
	privkeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: privkeyBytes,
		},
	)
	return (privkeyPem)
}
