package internal

import (
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/pkg/errors"
)

const federationSuffix = "/.well-known/openid-federation"

// EntityStatementObtainer is interface for a type obtaining entity configurations and entity statements
type EntityStatementObtainer interface {
	GetEntityConfiguration(entityID string) ([]byte, error)
	FetchEntityStatement(fetchEndpoint, subID, issID string) ([]byte, error)
	ListEntities(listEndpoint, entityType string) ([]byte, error)
}

type defaultHttpEntityStatementObtainer struct{}

// DefaultHttpEntityStatementObtainer is the default EntityStatementObtainer to obtain entity statements through http
var DefaultHttpEntityStatementObtainer defaultHttpEntityStatementObtainer

// GetEntityConfiguration implements the EntityStatementObtainer interface
// It returns the decoded entity configuration for a given entityID
func (defaultHttpEntityStatementObtainer) GetEntityConfiguration(entityID string) ([]byte, error) {
	uri := entityID
	if strings.HasSuffix(uri, "/") {
		uri = uri[:len(uri)-1]
	}
	uri += federationSuffix
	Logf("Obtaining entity configuration from %+q", uri)
	res, err := http.Get(uri)
	if err != nil {
		return nil, err
	}
	if status := res.StatusCode; status >= 300 {
		return nil, errors.Errorf("could not obtain entity statement, received status code %d", status)
	}
	return io.ReadAll(res.Body)
}

// FetchEntityStatement implements the EntityStatementObtainer interface
// It fetches and returns the decoded entity statement about a given entityID issued by issID
func (defaultHttpEntityStatementObtainer) FetchEntityStatement(fetchEndpoint, subID, issID string) ([]byte, error) {
	uri := fetchEndpoint
	params := url.Values{}
	params.Add("sub", subID)
	params.Add("iss", issID)
	uri += "?" + params.Encode()
	res, err := http.Get(uri)
	if err != nil {
		return nil, err
	}
	if status := res.StatusCode; status >= 300 {
		return nil, errors.Errorf("could not obtain entity statement, received status code %d", status)
	}
	return io.ReadAll(res.Body)
}

// ListEntities implements the EntityStatementObtainer interface
// It fetches and returns the entity list from the passed listendpoint
func (defaultHttpEntityStatementObtainer) ListEntities(listEndpoint, entityType string) ([]byte, error) {
	uri := listEndpoint
	params := url.Values{}
	params.Add("entity_type", entityType)
	uri += "?" + params.Encode()
	res, err := http.Get(uri)
	if err != nil {
		return nil, err
	}
	if status := res.StatusCode; status >= 300 {
		return nil, errors.Errorf("could not obtain entity statement, received status code %d", status)
	}
	return io.ReadAll(res.Body)
}
