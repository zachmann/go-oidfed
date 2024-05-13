package main

import (
	"os"

	"github.com/zachmann/go-oidfed/examples/ta/config"
	"github.com/zachmann/go-oidfed/examples/ta/oidfed"
	"github.com/zachmann/go-oidfed/examples/ta/server"
	"github.com/zachmann/go-oidfed/examples/ta/server/routes"
)

func main() {
	configFile := "config.yaml"
	if len(os.Args) > 1 {
		configFile = os.Args[1]
	}
	config.Load(configFile)
	routes.Init()
	oidfed.Init()
	server.Init()
	server.Start()
}
