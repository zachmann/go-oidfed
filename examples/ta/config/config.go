package config

import (
	"encoding/json"
	"log"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/zachmann/go-oidfed/pkg"
	"github.com/zachmann/go-oidfed/pkg/fedentities"
)

// Config holds configuration for the entity
type Config struct {
	ServerPort            int                   `yaml:"server_port"`
	EntityID              string                `yaml:"entity_id"`
	AuthorityHints        []string              `yaml:"authority_hints"`
	MetadataPolicyFile    string                `yaml:"metadata_policy_file"`
	MetadataPolicy        *pkg.MetadataPolicies `yaml:"-"`
	SigningKeyFile        string                `yaml:"signing_key_file"`
	ConfigurationLifetime int64                 `yaml:"configuration_lifetime"`
	OrganizationName      string                `yaml:"organization_name"`
	DataLocation          string                `yaml:"data_location"`
	ReadableStorage       bool                  `yaml:"human_readable_storage"`
	Endpoints             Endpoints             `yaml:"endpoints"`
}

// Endpoints holds configuration for the different possible endpoints
type Endpoints struct {
	FetchEndpoint   fedentities.EndpointConf `yaml:"fetch"`
	ListEndpoint    fedentities.EndpointConf `yaml:"list"`
	ResolveEndpoint fedentities.EndpointConf `yaml:"resolve"`
	//TODO
}

var c Config

// Get returns the Config
func Get() Config {
	return c
}

// Load loads the config from the given file
func Load(filename string) {
	content, err := os.ReadFile(filename)
	if err != nil {
		log.Fatal(err)
	}
	if err = yaml.Unmarshal(content, &c); err != nil {
		log.Fatal(err)
	}
	if c.EntityID == "" {
		log.Fatal("entity_id not set")
	}
	if c.SigningKeyFile == "" {
		log.Fatal("signing_key_file not set")
	}
	if c.ConfigurationLifetime == 0 {
		c.ConfigurationLifetime = 24 * 60 * 60
	}
	if c.DataLocation == "" {
		log.Fatal("data_location not set")
	}
	if c.MetadataPolicyFile == "" {
		log.Println("WARNING: metadata_policy_file not set")
	} else {
		policyContent, err := os.ReadFile(c.MetadataPolicyFile)
		if err != nil {
			log.Fatal(err)
		}
		if err = json.Unmarshal(policyContent, &c.MetadataPolicy); err != nil {
			log.Fatal(err)
		}
	}
}
