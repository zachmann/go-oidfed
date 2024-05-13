package routes

import (
	"log"
	"net/url"

	"github.com/zachmann/go-oidfed/examples/ta/config"
)

const (
	FederationConfigurationPath = "/.well-known/openid-federation"
	ListEndpointPath            = "/list"
	FetchEndpointPath           = "/fetch"
	EnrollEndpointPath          = "/enroll"
	DisenrollEndpointPath       = "/disenroll"
)

var (
	ListEndpointURI      string
	FetchEndpointURI     string
	EnrollEndpointURI    string
	DisenrollEndpointURI string
)

func Init() {
	baseURI := config.Get().EntityID
	var err error
	ListEndpointURI, err = url.JoinPath(baseURI, ListEndpointPath)
	if err != nil {
		log.Fatal(err)
	}
	FetchEndpointURI, err = url.JoinPath(baseURI, FetchEndpointPath)
	if err != nil {
		log.Fatal(err)
	}
	EnrollEndpointURI, err = url.JoinPath(baseURI, EnrollEndpointPath)
	if err != nil {
		log.Fatal(err)
	}
	DisenrollEndpointURI, err = url.JoinPath(baseURI, DisenrollEndpointPath)
	if err != nil {
		log.Fatal(err)
	}
}
