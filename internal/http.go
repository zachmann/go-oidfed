package internal

import (
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/google/go-querystring/query"
	"github.com/pkg/errors"

	"github.com/zachmann/go-oidfed/pkg/apimodel"
)

const federationSuffix = "/.well-known/openid-federation"

// EntityStatementObtainer is an interface for obtaining entity
// configurations and entity statements
type EntityStatementObtainer interface {
	GetEntityConfiguration(entityID string) ([]byte, error)
	FetchEntityStatement(fetchEndpoint, subID, issID string) ([]byte, error)
	ListEntities(listEndpoint, entityType string) ([]byte, error)
}

// ResolveObtainer is an interface for doing resolve requests
type ResolveObtainer interface {
	Resolve(endpoint string, request apimodel.ResolveRequest) ([]byte, error)
}

type defaultHttpEntityStatementObtainer struct{}
type defaultHttpResolveObtainer struct{}

// DefaultHttpEntityStatementObtainer is the default EntityStatementObtainer to obtain entity statements through http
var DefaultHttpEntityStatementObtainer defaultHttpEntityStatementObtainer

// DefaultHttpResolveObtainer is the default ResolveObtainer
var DefaultHttpResolveObtainer defaultHttpResolveObtainer

// GetEntityConfiguration implements the EntityStatementObtainer interface
// It returns the decoded entity configuration for a given entityID
func (defaultHttpEntityStatementObtainer) GetEntityConfiguration(entityID string) ([]byte, error) {
	uri := strings.TrimSuffix(entityID, "/") + federationSuffix
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

// Resolve implements the ResolveObtainer interface
func (defaultHttpResolveObtainer) Resolve(endpoint string, req apimodel.ResolveRequest) (
	[]byte,
	error,
) {
	uri := endpoint
	params, err := query.Values(req)
	if err != nil {
		return nil, errors.Errorf("could not generate query string: %s", err.Error())
	}
	uri += "?" + params.Encode()
	res, err := http.Get(uri)
	if err != nil {
		return nil, err
	}
	if status := res.StatusCode; status >= 300 {
		return nil, errors.Errorf("could not obtain resolve response, received status code %d", status)
	}
	return io.ReadAll(res.Body)
}
