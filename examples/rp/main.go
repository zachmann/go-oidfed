package main

import (
	"log"

	"github.com/lestrrat-go/jwx/v3/jwa"

	"github.com/zachmann/go-oidfed/pkg"
)

const fedSigningKeyName = "fed.signing.key"
const oidcSigningKeyName = "oidc.signing.key"

func main() {
	mustLoadConfig()
	initKeys(fedSigningKeyName, oidcSigningKeyName)
	for _, c := range conf.TrustMarks {
		if err := c.Verify(
			conf.EntityID, "",
			pkg.NewTrustMarkSigner(getKey(fedSigningKeyName), jwa.ES512()),
		); err != nil {
			log.Fatal(err)
		}
	}
	if conf.UseResolveEndpoint {
		pkg.DefaultMetadataResolver = pkg.SmartRemoteMetadataResolver{}
	}
	initServer()
}
