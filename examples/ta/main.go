package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/lestrrat-go/jwx/jwa"

	"github.com/zachmann/go-oidfed/examples/ta/config"
	"github.com/zachmann/go-oidfed/pkg"
	"github.com/zachmann/go-oidfed/pkg/fedentities"
	"github.com/zachmann/go-oidfed/pkg/fedentities/storage"
)

func main() {
	configFile := "config.yaml"
	if len(os.Args) > 1 {
		configFile = os.Args[1]
	}
	config.Load(configFile)
	log.Println("Loaded Config")
	c := config.Get()
	initKey()
	log.Println("Loaded signing key")

	var subordinateStorage storage.SubordinateStorageBackend
	if c.ReadableStorage {
		warehouse := storage.NewFileStorage(c.DataLocation)
		subordinateStorage = warehouse.SubordinateStorage()
	} else {
		warehouse, err := storage.NewBadgerStorage(c.DataLocation)
		if err != nil {
			log.Fatal(err)
		}
		subordinateStorage = warehouse.SubordinateStorage()
	}
	log.Println("Loaded storage backend")

	entity, err := fedentities.NewFedEntity(
		c.EntityID, c.AuthorityHints,
		&pkg.Metadata{
			FederationEntity: &pkg.FederationEntityMetadata{
				CommonMetadata: pkg.CommonMetadata{
					OrganizationName: c.OrganizationName,
				},
			},
		},
		signingKey, jwa.ES512, c.ConfigurationLifetime, fedentities.SubordinateStatementsConfig{
			MetadataPolicies: nil,
			Configs: map[string]*fedentities.SubordinateStatementTypeConfig{
				"": {
					SubordinateStatementLifetime: 3600,
					// TODO read all of this from config or a storage backend
				},
			},
		},
	)
	if err != nil {
		panic(err)
	}
	entity.MetadataPolicies = c.MetadataPolicy
	// TODO other constraints etc.
	log.Println("Initialized Entity")

	entity.AddFetchEndpoint(c.Endpoints.FetchEndpoint, subordinateStorage)
	entity.AddSubordinateListingEndpoint(c.Endpoints.ListEndpoint, subordinateStorage)
	entity.AddResolveEndpoint(c.Endpoints.ResolveEndpoint)
	log.Println("Added Endpoints")

	// subordinateStorage.Write(
	// 	"https://op.example.org", storage.SubordinateInfo{
	// 		JWKS:       genJWKS(),
	// 		EntityType: constants.EntityTypeOpenIDProvider,
	// 		EntityID:   "https://op.example.org",
	// 	},
	// )
	// subordinateStorage.Write(
	// 	"https://rp.example.org", storage.SubordinateInfo{
	// 		JWKS:       genJWKS(),
	// 		EntityType: constants.EntityTypeOpenIDRelyingParty,
	// 		EntityID:   "https://rp.example.org",
	// 	},
	// )

	log.Printf("Start serving on port %d\n", c.ServerPort)
	if err = http.ListenAndServe(fmt.Sprintf(":%d", c.ServerPort), entity.HttpHandlerFunc()); err != nil {
		panic(err)
	}
	// if err = entity.Listen(fmt.Sprintf(":%d", c.ServerPort)); err != nil {
	// 	panic(err)
	// }

}
