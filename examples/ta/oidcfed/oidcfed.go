package oidcfed

import (
	"log"
	"net/http"
	"time"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/pkg/errors"

	"github.com/zachmann/go-oidcfed/examples/ta/config"
	"github.com/zachmann/go-oidcfed/examples/ta/server/routes"
	"github.com/zachmann/go-oidcfed/examples/ta/storage"
	"github.com/zachmann/go-oidcfed/internal"
	"github.com/zachmann/go-oidcfed/internal/utils"
	"github.com/zachmann/go-oidcfed/pkg"
)

var fedEntity *pkg.FederationEntity
var ownMetadata *pkg.Metadata

var store storage.JWKStorageBackend
var entityStatementObtainer = internal.DefaultHttpEntityStatementObtainer

func Init() {
	initKey()
	store = make(storage.JWKSFileStorage)
	if err := store.Load(); err != nil {
		log.Fatal(err)
	}
	var err error
	ownMetadata = &pkg.Metadata{
		FederationEntity: &pkg.FederationEntityMetadata{
			FederationFetchEndpoint: routes.FetchEndpointURI,
			FederationListEndpoint:  routes.ListEndpointURI,
			OrganizationName:        config.Get().OrganizationName,
			Extra:                   map[string]interface{}{"enrollment_endpoint": routes.EnrollEndpointURI},
		},
	}
	fedEntity, err = pkg.NewFederationEntity(
		config.Get().EntityID, config.Get().AuthorityHints,
		ownMetadata, signingKey, jwa.ES512, config.Get().ConfigurationLifetime,
	)
	if err != nil {
		log.Fatal(err)
	}
}

func GetEntityConfiguration() *pkg.EntityConfiguration {
	return fedEntity.EntityConfiguration()
}

func EnrollEntity(entityID, entityType string) (int, error) {
	body, err := entityStatementObtainer.GetEntityConfiguration(entityID)
	if err != nil {
		log.Printf("Could not obtain entity configuration for %+q", entityID)
		return http.StatusNotFound, err
	}
	stmt, err := pkg.ParseEntityStatement(body)
	if err != nil {
		log.Printf("Could not parse entity configuration: %s", body)
		return http.StatusBadRequest, err
	}
	if stmt.Issuer != entityID {
		return http.StatusBadRequest,
			errors.New("error verifying entity configuration: iss does not macht entity id")
	}
	if stmt.Subject != entityID {
		return http.StatusBadRequest,
			errors.New("error verifying entity configuration: sub does not macht entity id")
	}
	if !utils.SliceContains(config.Get().EntityID, stmt.AuthorityHints) {
		return http.StatusBadRequest,
			errors.New(
				"error verifying entity configuration: we are not included in authority_hints" +
					" entity id",
			)
	}
	if stmt.JWKS == nil || stmt.JWKS.Len() == 0 {
		return http.StatusBadRequest, errors.New("error verifying entity configuration: no jwks found")
	}
	if entityType == "" {
		m := stmt.Metadata
		if m == nil {
			return http.StatusBadRequest,
				errors.New("entity_type parameter not given and could not detect entity type from metadata")
		}
		if m.OpenIDProvider != nil {
			entityType = "openid_provider"
		} else if m.RelyingParty != nil {
			entityType = "openid_relying_party"
		} else if m.OAuthAuthorizationServer != nil {
			entityType = "oauth_authorization_server"
		} else if m.OAuthClient != nil {
			entityType = "oauth_client"
		} else if m.OAuthProtectedResource != nil {
			entityType = "oauth_resource"
		} else if m.FederationEntity != nil {
			entityType = "federation_entity"
		} else {
			return http.StatusBadRequest,
				errors.New("entity_type parameter not given and could not detect entity type from metadata")
		}
	}
	if err = store.Write(
		entityID, storage.SubordinateInfo{
			JWKS:       stmt.JWKS,
			EntityType: entityType,
			EntityID:   entityID,
		},
	); err != nil {
		return http.StatusInternalServerError, err
	}
	return http.StatusOK, nil
}

func ListSubordinates(entityType string) ([]string, error) {
	return store.ListSubordinates(entityType)
}

func FetchEntityStatement(sub string) ([]byte, int, error) {
	info, err := store.Read(sub)
	if err != nil {
		return nil, http.StatusNotFound, err
	}
	now := time.Now()
	payload := pkg.EntityStatementPayload{
		Issuer:         config.Get().EntityID,
		Subject:        info.EntityID,
		IssuedAt:       pkg.Unixtime{Time: now},
		ExpiresAt:      pkg.Unixtime{Time: now.Add(time.Second * time.Duration(config.Get().ConfigurationLifetime))},
		JWKS:           info.JWKS,
		SourceEndpoint: routes.FetchEndpointURI,
		MetadataPolicy: config.Get().MetadataPolicy,
	}
	data, err := fedEntity.SignEntityStatement(payload)
	if err != nil {
		return nil, 0, err
	}
	return data, http.StatusOK, nil
}
