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
	var trustMarkedEntitiesStorage storage.TrustMarkedEntitiesStorageBackend
	if c.ReadableStorage {
		warehouse := storage.NewFileStorage(c.DataLocation)
		subordinateStorage = warehouse.SubordinateStorage()
		trustMarkedEntitiesStorage = warehouse.TrustMarkedEntitiesStorage()
	} else {
		warehouse, err := storage.NewBadgerStorage(c.DataLocation)
		if err != nil {
			log.Fatal(err)
		}
		subordinateStorage = warehouse.SubordinateStorage()
		trustMarkedEntitiesStorage = warehouse.TrustMarkedEntitiesStorage()
	}
	log.Println("Loaded storage backend")

	entity, err := fedentities.NewFedEntity(
		c.EntityID, c.AuthorityHints,
		&pkg.Metadata{
			FederationEntity: &pkg.FederationEntityMetadata{
				OrganizationName: c.OrganizationName,
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

	if len(c.TrustMarkSpecs) > 0 {
		entity.TrustMarkIssuer = pkg.NewTrustMarkIssuer(
			c.EntityID, entity.GeneralJWTSigner.TrustMarkSigner(), c.TrustMarkSpecs,
		)
	}
	log.Println("Initialized Entity")

	if endpoint := c.Endpoints.FetchEndpoint; endpoint.IsSet() {
		entity.AddFetchEndpoint(endpoint, subordinateStorage)
	}
	if endpoint := c.Endpoints.ListEndpoint; endpoint.IsSet() {
		entity.AddSubordinateListingEndpoint(endpoint, subordinateStorage)
	}
	if endpoint := c.Endpoints.ResolveEndpoint; endpoint.IsSet() {
		entity.AddResolveEndpoint(endpoint)
	}
	if endpoint := c.Endpoints.TrustMarkStatusEndpoint; endpoint.IsSet() {
		entity.AddTrustMarkStatusEndpoint(endpoint, trustMarkedEntitiesStorage)
	}
	if endpoint := c.Endpoints.TrustMarkedEntitiesListingEndpoint; endpoint.IsSet() {
		entity.AddTrustMarkedEntitiesListingEndpoint(endpoint, trustMarkedEntitiesStorage)
	}
	if endpoint := c.Endpoints.TrustMarkEndpoint; endpoint.IsSet() {
		entity.AddTrustMarkEndpoint(endpoint, trustMarkedEntitiesStorage)
	}
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
