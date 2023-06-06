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
	"path"

	"github.com/golang-jwt/jwt"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
)

func mustNewKey() *ecdsa.PrivateKey {
	sk, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	return sk
}

func mustLoadKey(name string) crypto.Signer {
	data, err := os.ReadFile(path.Join(conf.KeyStorage, name))
	if err != nil {
		sk := mustNewKey()
		if err = os.WriteFile(path.Join(conf.KeyStorage, name), exportECPrivateKeyAsPem(sk), 0600); err != nil {
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

var keys map[string]crypto.Signer
var jwks map[string]jwk.Set

func initKeys(names ...string) {
	keys = make(map[string]crypto.Signer)
	jwks = make(map[string]jwk.Set)
	for _, name := range names {
		keys[name] = mustLoadKey(name)

		key, err := jwk.New(keys[name].Public())
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
		set := jwk.NewSet()
		set.Add(key)
		jwks[name] = set
	}
}

func getKey(name string) crypto.Signer {
	return keys[name]
}
func getJWKS(name string) jwk.Set {
	return jwks[name]
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
