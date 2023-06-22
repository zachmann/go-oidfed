package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jws"

	"github.com/zachmann/go-oidcfed/examples/rp/pkce"
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

const userHtml = `<!DOCTYPE html>
<html>
<body>
<h3>Hello %s@%s</h3>
<a href="/">Back to Login</a>
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

type stateData struct {
	codeChallange *pkce.PKCE
	tokenEndpoint string
	issuer        string
}

var stateDB map[string]stateData

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
	state := randASCIIString(32)
	pkceChallenge := pkce.NewS256PKCE(randASCIIString(20))
	stateDB[state] = stateData{
		codeChallange: pkceChallenge,
		tokenEndpoint: opMetadata.TokenEndpoint,
		issuer:        opMetadata.Issuer,
	}
	challenge, err := pkceChallenge.Challenge()
	if err != nil {
		log.Fatal(err)
	}
	requestParams := map[string]any{
		"aud":           opMetadata.Issuer,
		"redirect_uri":  redirectURI,
		"prompt":        "consent",
		"state":         state,
		"response_type": "code",
		"scope": []string{
			"openid",
		},
		"nonce":                 randASCIIString(32),
		"code_challenge":        challenge,
		"code_challenge_method": pkce.TransformationS256.String(),
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
	q.Set("response_type", "code")
	q.Set("scope", "openid")
	q.Set("redirect_uri", redirectURI)
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusSeeOther)
}

func handleCodeExchange(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	e := r.URL.Query().Get("error")
	errorDescription := r.URL.Query().Get("error_description")
	if e != "" {
		if errorDescription != "" {
			e += ": " + errorDescription
		}
		w.WriteHeader(444)
		io.WriteString(w, e)
		return
	}
	stateInfo, found := stateDB[state]
	if !found {
		w.WriteHeader(444)
		io.WriteString(w, "state mismatch")
		return
	}
	clientAssertion, err := authBuilder.ClientAssertion(stateInfo.tokenEndpoint)
	if err != nil {
		log.Fatal(err)
	}
	params := url.Values{}
	params.Set("grant_type", "authorization_code")
	params.Set("code_verifier", stateInfo.codeChallange.Verifier())
	params.Set("code", code)
	params.Set("redirect_uri", redirectURI)
	params.Set("client_id", conf.EntityID)
	params.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	params.Set("client_assertion", string(clientAssertion))
	res, err := http.PostForm(stateInfo.tokenEndpoint, params)
	if err != nil {
		w.WriteHeader(500)
		io.WriteString(w, err.Error())
		return
	}
	body, err := io.ReadAll(res.Body)
	if err != nil {
		w.WriteHeader(500)
		io.WriteString(w, err.Error())
		return
	}
	resData := map[string]any{}
	err = json.Unmarshal(body, &resData)
	if err != nil {
		w.WriteHeader(500)
		io.WriteString(w, err.Error())
		return
	}
	msg, err := jws.ParseString(resData["id_token"].(string))
	if err != nil {
		w.WriteHeader(500)
		io.WriteString(w, err.Error())
		return
	}
	delete(stateDB, state)
	msgData := map[string]any{}
	err = json.Unmarshal(msg.Payload(), &msgData)
	if err != nil {
		w.WriteHeader(500)
		io.WriteString(w, err.Error())
		return
	}

	w.WriteHeader(res.StatusCode)
	io.WriteString(w, fmt.Sprintf(userHtml, msgData["sub"], msgData["iss"]))
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
				RedirectURIS:            []string{redirectURI},
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
	stateDB = make(map[string]stateData)

	http.HandleFunc("/", handleHome)
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/redirect", handleCodeExchange)
	http.HandleFunc("/.well-known/openid-federation", handleEntityConfiguration)

	fmt.Printf("Serving on %s\n", conf.ServerAddr)
	if err := http.ListenAndServe(conf.ServerAddr, nil); err != nil {
		log.Fatal(err)
	}
}
