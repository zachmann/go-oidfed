package config

import (
	"encoding/json"
	"log"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/zachmann/go-oidfed/pkg"
)

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
}

var c Config

func Get() Config {
	return c
}

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
	}
	policyContent, err := os.ReadFile(c.MetadataPolicyFile)
	if err != nil {
		log.Fatal(err)
	}
	if err = json.Unmarshal(policyContent, &c.MetadataPolicy); err != nil {
		log.Fatal(err)
	}

}
