package main

import (
	"log"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/zachmann/go-oidfed/pkg"
)

type config struct {
	EntityID           string             `yaml:"entity_id"`
	TrustAnchors       pkg.TrustAnchors   `yaml:"trust_anchors"`
	AuthorityHints     []string           `yaml:"authority_hints"`
	OrganisationName   string             `yaml:"organisation_name"`
	ServerAddr         string             `yaml:"server_addr"`
	KeyStorage         string             `yaml:"key_storage"`
	OnlyAutomaticOPs   bool               `yaml:"filter_to_automatic_ops"`
	EnableDebugLog     bool               `yaml:"enable_debug_log"`
	TrustMarks         pkg.TrustMarkInfos `yaml:"trust_marks"`
	UseResolveEndpoint bool               `yaml:"use_resolve_endpoint"`
}

var conf *config

func mustLoadConfig() {
	data, err := os.ReadFile("config.yaml")
	if err != nil {
		log.Fatal(err)
	}
	conf = &config{}
	if err = yaml.Unmarshal(data, conf); err != nil {
		log.Fatal(err)
	}
	if conf.KeyStorage == "" {
		log.Fatal("key_storage must be given")
	}
	d, err := os.Stat(conf.KeyStorage)
	if err != nil {
		log.Fatal(err)
	}
	if !d.IsDir() {
		log.Fatalf("key_storage '%s' must be a directory", conf.KeyStorage)
	}
	if conf.EnableDebugLog {
		pkg.EnableDebugLogging()
	}
}
