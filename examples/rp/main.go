package main

import (
	"github.com/zachmann/go-oidfed/pkg"
)

func main() {
	mustLoadConfig()
	initKeys("fed.signing.key", "oidc.signing.key")
	if conf.UseResolveEndpoint {
		pkg.DefaultMetadataResolver = pkg.SmartRemoteMetadataResolver{}
	}
	initServer()
}
