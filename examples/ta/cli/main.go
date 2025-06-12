package main

import (
	"log"

	"github.com/spf13/cobra"

	"github.com/go-oidfed/lib/examples/ta/config"
	"github.com/go-oidfed/lib/pkg/fedentities/storage"
)

var rootCmd = &cobra.Command{
	Use:   "tacli",
	Short: "tacli can help you manage your TA",
	Long:  "tacli can help you manage your TA or IA",
	RunE:  rootRunE,
}

var configFile string
var subordinateStorage storage.SubordinateStorageBackend
var trustMarkedEntitiesStorage storage.TrustMarkedEntitiesStorageBackend

func loadConfig() error {
	if configFile == "" {
		configFile = "config.yaml"
	}
	config.Load(configFile)
	log.Println("Loaded Config")
	c := config.Get()

	var err error
	subordinateStorage, trustMarkedEntitiesStorage, err = config.LoadStorageBackends(c)
	if err != nil {
		log.Fatal(err)
	}
	return nil
}

func rootRunE(cmd *cobra.Command, args []string) error {
	return loadConfig()
}

func main() {
	rootCmd.Flags().StringVarP(&configFile, "config", "c", "config.yaml", "the config file to use")
	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}
