package config

import (
	"encoding/json"
	"log"
	"os"

	"github.com/fatih/structs"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v3"

	"github.com/zachmann/go-oidfed/internal/utils"
	"github.com/zachmann/go-oidfed/pkg"
	"github.com/zachmann/go-oidfed/pkg/fedentities"
)

// Config holds configuration for the entity
type Config struct {
	ServerPort            int                                       `yaml:"server_port"`
	EntityID              string                                    `yaml:"entity_id"`
	AuthorityHints        []string                                  `yaml:"authority_hints"`
	MetadataPolicyFile    string                                    `yaml:"metadata_policy_file"`
	MetadataPolicy        *pkg.MetadataPolicies                     `yaml:"-"`
	SigningKeyFile        string                                    `yaml:"signing_key_file"`
	ConfigurationLifetime int64                                     `yaml:"configuration_lifetime"`
	OrganizationName      string                                    `yaml:"organization_name"`
	DataLocation          string                                    `yaml:"data_location"`
	ReadableStorage       bool                                      `yaml:"human_readable_storage"`
	Endpoints             Endpoints                                 `yaml:"endpoints"`
	TrustMarkSpecs        []extendedTrustMarkSpec                   `yaml:"trust_mark_specs"`
	TrustMarks            []*pkg.EntityConfigurationTrustMarkConfig `yaml:"trust_marks"`
	TrustMarkIssuers      pkg.AllowedTrustMarkIssuers               `yaml:"trust_mark_issuers"`
	TrustMarkOwners       pkg.TrustMarkOwners                       `yaml:"trust_mark_owners"`
}

type extendedTrustMarkSpec struct {
	CheckerConfig     fedentities.EntityCheckerConfig `yaml:"checker"`
	pkg.TrustMarkSpec `yaml:",inline"`
}

// UnmarshalYAML implements the yaml.Unmarshaler interface
func (e *extendedTrustMarkSpec) UnmarshalYAML(node *yaml.Node) error {
	type forChecker struct {
		CheckerConfig fedentities.EntityCheckerConfig `yaml:"checker"`
	}
	mm := e.TrustMarkSpec
	var fc forChecker

	if err := node.Decode(&fc); err != nil {
		return errors.WithStack(err)
	}
	if err := node.Decode(&mm); err != nil {
		return errors.WithStack(err)
	}
	extra := make(map[string]interface{})
	if err := node.Decode(&extra); err != nil {
		return errors.WithStack(err)
	}
	s1 := structs.New(fc)
	s2 := structs.New(mm)
	for _, tag := range utils.FieldTagNames(s1.Fields(), "yaml") {
		delete(extra, tag)
	}
	for _, tag := range utils.FieldTagNames(s2.Fields(), "yaml") {
		delete(extra, tag)
	}
	if len(extra) == 0 {
		extra = nil
	}

	mm.Extra = extra
	e.TrustMarkSpec = mm
	e.CheckerConfig = fc.CheckerConfig
	e.IncludeExtraClaimsInInfo = true
	return nil
}

// Endpoints holds configuration for the different possible endpoints
type Endpoints struct {
	FetchEndpoint                      fedentities.EndpointConf `yaml:"fetch"`
	ListEndpoint                       fedentities.EndpointConf `yaml:"list"`
	ResolveEndpoint                    fedentities.EndpointConf `yaml:"resolve"`
	TrustMarkStatusEndpoint            fedentities.EndpointConf `yaml:"trust_mark_status"`
	TrustMarkedEntitiesListingEndpoint fedentities.EndpointConf `yaml:"trust_mark_list"`
	TrustMarkEndpoint                  fedentities.EndpointConf `yaml:"trust_mark"`
	HistoricalKeysEndpoint             fedentities.EndpointConf `yaml:"historical_keys"`

	EnrollmentEndpoint extendedEndpointConfig `yaml:"enroll"`
}

type extendedEndpointConfig struct {
	fedentities.EndpointConf `yaml:",inline"`
	CheckerConfig            fedentities.EntityCheckerConfig `yaml:"checker"`
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
	for _, tmc := range c.TrustMarks {
		if err = tmc.Verify(c.EntityID); err != nil {
			log.Fatal(err)
		}
	}
}
