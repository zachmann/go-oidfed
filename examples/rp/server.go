package main

import (
	"crypto/rand"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"

	"github.com/lestrrat-go/jwx/jwa"

	"github.com/zachmann/go-oidcfed/internal/utils"
	"github.com/zachmann/go-oidcfed/pkg"
)

const loginHtml = `<!DOCTYPE html>
<html>
<body>
<h1>Choose an OP from the supported federations to login</h1>
<form action="login">
  <select name="op" id="op">
	<option value="/" selected disabled>Choose OP...</option>
	%s
  </select>
  <input type="submit" value="Login">
</form>
</body>
</html>`

func handleHome(w http.ResponseWriter, r *http.Request) {
	const opOptionFmt = `<option value="%s">%s</option>`
	var options string
	filters := []pkg.OPDiscoveryFilter{}
	if conf.OnlyAutomaticOPs {
		filters = append(filters, pkg.OPDiscoveryFilterAutomaticRegistration)
	}
	ops := pkg.FilterableVerifiedChainsOPDiscoverer{
		Filters: filters,
	}.Discover(conf.TrustAnchors...)
	for _, op := range ops {
		options += fmt.Sprintf(opOptionFmt, op.Issuer, utils.FirstNonEmpty(op.OrganizationName, op.Issuer))
	}
	io.WriteString(w, fmt.Sprintf(loginHtml, options))
}

var stateDB map[string]struct{}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if authBuilder == nil {
		authBuilder = pkg.NewRequestObjectProducer(conf.EntityID, getKey("oidc"), jwa.ES512, 60)
	}
	op := r.URL.Query().Get("op")
	resolver := pkg.TrustResolver{
		TrustAnchors:   conf.TrustAnchors,
		StartingEntity: op,
	}
	chains := resolver.ResolveToValidChains()
	chains = chains.Filter(pkg.TrustChainsFilterMinPathLength)
	chain := chains[0]
	metadata, err := chain.Metadata()
	if err != nil {
		w.WriteHeader(400)
		io.WriteString(w, err.Error())
		return
	}
	opMetadata := metadata.OpenIDProvider
	state := make([]byte, 20)
	if _, err = rand.Read(state); err != nil {
		log.Fatal(err)
	}
	stateDB[string(state)] = struct{}{}
	requestParams := map[string]any{
		"aud":           opMetadata.Issuer,
		"redirect_uri":  redirectURI,
		"prompt":        "consent",
		"state":         string(state),
		"response_type": "code",
	}
	requestObject, err := authBuilder.RequestObject(requestParams)
	if err != nil {
		log.Fatal(err)
	}
	u, err := url.Parse(opMetadata.AuthorizationEndpoint)
	if err != nil {
		log.Fatal(err)
	}
	q := url.Values{}
	q.Set("request", string(requestObject))
	q.Set("client_id", conf.EntityID)
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusSeeOther)
}

var authBuilder *pkg.RequestObjectProducer
var fedLeaf *pkg.FederationLeaf

var redirectURI string

func handleEntityConfiguration(w http.ResponseWriter, r *http.Request) {
	var err error
	if fedLeaf == nil {
		metadata := &pkg.Metadata{
			RelyingParty: &pkg.OpenIDRelyingPartyMetadata{
				Scope:                   "openid profile email",
				RedirectURIS:            []string{},
				ResponseTypes:           []string{"code"},
				GrantTypes:              []string{"authorization_code"},
				ApplicationType:         "web",
				ClientName:              "example go oidcfed rp",
				JWKS:                    getJWKS("oidc"),
				OrganizationName:        conf.OrganisationName,
				ClientRegistrationTypes: []string{"automatic"},
			},
			FederationEntity: &pkg.FederationEntityMetadata{
				OrganizationName: conf.OrganisationName,
			},
		}
		fedLeaf, err = pkg.NewFederationLeaf(
			conf.EntityID, conf.AuthorityHints, conf.TrustAnchors, metadata, getKey("fed"),
			jwa.ES512, 86400,
		)
		if err != nil {
			log.Fatal(err)
		}
	}
	c := fedLeaf.EntityConfiguration()
	jwt, err := c.JWT()
	if err != nil {
		log.Fatal(err)
	}
	w.Header().Set("Content-Type", "application/entity-statement+jwt")
	w.Write(jwt)
}

func initServer() {
	redirectURI = fmt.Sprintf("%s/%s", conf.EntityID, "redirect")
	stateDB = make(map[string]struct{})

	http.HandleFunc("/", handleHome)
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/.well-known/openid-federation", handleEntityConfiguration)

	fmt.Printf("Serving on %s\n", conf.ServerAddr)
	if err := http.ListenAndServe(conf.ServerAddr, nil); err != nil {
		log.Fatal(err)
	}
}
