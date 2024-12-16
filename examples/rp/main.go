package main

import (
	"github.com/zachmann/go-oidfed/pkg"
)

const fedSigningKeyName = "fed.signing.key"
const oidcSigningKeyName = "oidc.signing.key"

func main() {
	mustLoadConfig()
	initKeys(fedSigningKeyName, oidcSigningKeyName)
	if conf.UseResolveEndpoint {
		pkg.DefaultMetadataResolver = pkg.SmartRemoteMetadataResolver{}
	}
	initServer()
}
