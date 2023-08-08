package main

import (
	"os"

	"github.com/zachmann/go-oidcfed/examples/ta/config"
	"github.com/zachmann/go-oidcfed/examples/ta/oidcfed"
	"github.com/zachmann/go-oidcfed/examples/ta/server"
	"github.com/zachmann/go-oidcfed/examples/ta/server/routes"
)

func main() {
	configFile := "config.yaml"
	if len(os.Args) > 1 {
		configFile = os.Args[1]
	}
	config.Load(configFile)
	routes.Init()
	oidcfed.Init()
	server.Init()
	server.Start()
}
