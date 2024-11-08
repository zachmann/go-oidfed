package main

import (
	"github.com/zachmann/go-oidfed/pkg"
)

func main() {
	mustLoadConfig()
	initKeys("fed", "oidc")
	if conf.UseResolveEndpoint {
		pkg.DefaultMetadataResolver = pkg.SmartRemoteMetadataResolver{}
	}
	initServer()
}
