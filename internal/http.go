package internal

import (
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/pkg/errors"
)

const federationSuffix = "/.well-known/openid-federation"

type EntityStatementObtainer interface {
	GetEntityConfiguration(entityID string) ([]byte, error)
	FetchEntityStatement(fetchEndpoint, subID, issID string) ([]byte, error)
}

type defaultHttpEntityStatementObtainer struct{}

// DefaultHttpEntityStatementObtainer is the default EntityStatementObtainer to obtain entity statements through http
var DefaultHttpEntityStatementObtainer defaultHttpEntityStatementObtainer

func (o defaultHttpEntityStatementObtainer) GetEntityConfiguration(entityID string) ([]byte, error) {
	url := entityID
	if strings.HasSuffix(url, "/") {
		url = url[:len(url)-1]
	}
	url += federationSuffix
	res, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	if status := res.StatusCode; status >= 300 {
		return nil, errors.Errorf("could not obtain entity statement, received status code %d", status)
	}
	return io.ReadAll(res.Body)
}

func (o defaultHttpEntityStatementObtainer) FetchEntityStatement(fetchEndpoint, subID, issID string) ([]byte, error) {
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
