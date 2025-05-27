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

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"

	"github.com/zachmann/go-oidfed/examples/ta/config"
	myjwk "github.com/zachmann/go-oidfed/pkg/jwk"
)

func genJWKS() myjwk.JWKS {
	sk := mustNewKey()
	jwks := myjwk.KeyToJWKS(sk.Public(), jwa.ES512())
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
	block, _ := pem.Decode(data)
	sk, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		log.Fatal(err)
	}
	return sk
}

var signingKey crypto.Signer
var signingJWKS jwk.Set

func initKey() {
	signingKey = mustLoadKey()

	key, err := jwk.PublicKeyOf(signingKey.Public())
	if err != nil {
		log.Fatal(err)
	}
	if err = jwk.AssignKeyID(key); err != nil {
		log.Fatal(err)
	}
	if err = key.Set(jwk.KeyUsageKey, jwk.ForSignature); err != nil {
		log.Fatal(err)
	}
	if err = key.Set(jwk.AlgorithmKey, jwa.ES512()); err != nil {
		log.Fatal(err)
	}
	signingJWKS = jwk.NewSet()
	signingJWKS.AddKey(key)
}

func exportECPrivateKeyAsPem(privkey *ecdsa.PrivateKey) []byte {
	privkeyBytes, _ := x509.MarshalECPrivateKey(privkey)
	privkeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: privkeyBytes,
		},
	)
	return privkeyPem
}
