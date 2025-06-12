package pkg

import (
	"net/http"
	"strings"

	"github.com/jarcoal/httpmock"

	"github.com/go-oidfed/lib/constants"
)

type mockedEntityConfigurationSigner interface {
	EntityConfigurationJWT() ([]byte, error)
}
type mockedFetchResponder interface {
	FetchResponse(sub string) ([]byte, error)
}
type mockedSubordinateLister interface {
	Subordinates(entityType string) ([]string, error)
}

func mockEntityConfiguration(entityID string, signer mockedEntityConfigurationSigner) {
	uri := strings.TrimSuffix(entityID, "/") + constants.FederationSuffix
	httpmock.RegisterResponder(
		"GET", uri, func(_ *http.Request) (*http.Response, error) {
			res, err := signer.EntityConfigurationJWT()
			if err != nil {
				return nil, err
			}
			return httpmock.NewBytesResponse(200, res), nil
		},
	)
}

func mockFetchEndpoint(fetchEndpoint string, mocker mockedFetchResponder) {
	httpmock.RegisterResponder(
		"GET", fetchEndpoint, func(request *http.Request) (*http.Response, error) {
			sub := request.URL.Query().Get("sub")
			res, err := mocker.FetchResponse(sub)
			if err != nil {
				return nil, err
			}
			return httpmock.NewBytesResponse(200, res), nil
		},
	)
}

func mockListEndpoint(listEndpoint string, mocker mockedSubordinateLister) {
	httpmock.RegisterResponder(
		"GET", listEndpoint, func(request *http.Request) (*http.Response, error) {
			entityType := request.URL.Query().Get("entity_type")
			entities, err := mocker.Subordinates(entityType)
			if err != nil {
				return nil, err
			}
			return httpmock.NewJsonResponse(200, entities)
		},
	)
}
