package pkg

import (
	"crypto"
	"encoding/json"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/pkg/errors"
)

var key crypto.PrivateKey
var sign func(payload []byte) ([]byte, error)

func Init(k crypto.PrivateKey, signingAlg jwa.SignatureAlgorithm) {
	key = k
	sign = func(payload []byte) ([]byte, error) {
		headers := jws.NewHeaders()
		if err := headers.Set(jws.TypeKey, "entity-statement+jwt"); err != nil {
			return nil, err
		}
		return jws.Sign(payload, signingAlg, key, jws.WithHeaders(headers))
	}
}

type EntityStatement struct {
	Issuer                           string                   `json:"iss"`
	Subject                          string                   `json:"sub"`
	IssuedAt                         int64                    `json:"iat"`
	ExpiresAt                        int64                    `json:"exp"`
	JWKS                             jwk.Set                  `json:"jwks"`
	Audience                         string                   `json:"aud,omitempty"`
	AuthorityHints                   []string                 `json:"authority_hints,omitempty"`
	Metadata                         *Metadata                `json:"metadata,omitempty"`
	MetadataPolicy                   *MetadataPolicy          `json:"metadata_policy,omitempty"`
	Constraints                      *ConstraintSpecification `json:"constraints,omitempty"`
	CriticalExtensions               []string                 `json:"crit,omitempty"`
	CriticalPolicyLanguageExtensions []string                 `json:"policy_language_crit,omitempty"`
	TrustMarks                       []TrustMark              `json:"trust_marks,omitempty"`
	TrustMarksIssuers                *AllowedTrustMarkIssuers `json:"trust_marks_issuers,omitempty"`
	TrustAnchorID                    string                   `json:"trust_anchor_id,omitempty"`
	Extra                            map[string]interface{}   `json:"-"`
}

type Metadata struct {
	OpenIDProvider           *OpenIDProviderMetadata           `json:"openid_provider,omitempty"`
	RelyingParty             *OpenIDRelyingPartyMetadata       `json:"openid_relying_party,omitempty"`
	OAuthAuthorizationServer *OAuthAuthorizationServerMetadata `json:"oauth_authorization_server,omitempty"`
	OAuthClient              *OAuthClientMetadata              `json:"oauth_client,omitempty"`
	OAuthProtectedResource   *OAuthProtectedResourceMetadata   `json:"oauth_resource,omitempty"`
	FederationEntity         *FederationEntityMetadata         `json:"federation_entity,omitempty"`
}

type MetadataPolicy struct {
	OpenIDProvider           *OpenIDProviderMetadataPolicy           `json:"openid_provider,omitempty"`
	RelyingParty             *OpenIDRelyingPartyMetadataPolicy       `json:"openid_relying_party,omitempty"`
	OAuthAuthorizationServer *OAuthAuthorizationServerMetadataPolicy `json:"oauth_authorization_server,omitempty"`
	OAuthClient              *OAuthClientMetadataPolicy              `json:"oauth_client,omitempty"`
	OAuthProtectedResource   *OAuthProtectedResourceMetadataPolicy   `json:"oauth_resource,omitempty"`
	FederationEntity         *FederationEntityMetadataPolicy         `json:"federation_entity,omitempty"`
}

type ClaimValue interface {
	bool | string | int | int64 | uint | uint64
}
type SlicedClaimValue interface {
	[]string
}

type PolicyOperators[V ClaimValue] struct {
	Value   V                     `json:"value,omitempty"`
	Add     SliceOrSingleValue[V] `json:"add,omitempty"`
	Default V                     `json:"default,omitempty"`

	Essential bool `json:"essential,omitempty"`
	OneOf     []V  `json:"one_of,omitempty"`

	Extra map[string]interface{} `json:"-"`
}
type PolicyOperatorsSliced[V SlicedClaimValue] struct {
	Value   V `json:"value,omitempty"`
	Add     V `json:"add,omitempty"`
	Default V `json:"default,omitempty"`

	Essential  bool `json:"essential,omitempty"`
	SubsetOf   V    `json:"subset_of,omitempty"`
	SupersetOf V    `json:"superset_of,omitempty"`

	Extra map[string]interface{} `json:"-"`
}
type JWKSPolicyOperators struct {
	Value   jwk.Set `json:"value,omitempty"`
	Add     jwk.Set `json:"add,omitempty"`
	Default jwk.Set `json:"default,omitempty"`

	Essential  bool    `json:"essential,omitempty"`
	SubsetOf   jwk.Set `json:"subset_of,omitempty"`
	SupersetOf jwk.Set `json:"superset_of,omitempty"`

	Extra map[string]interface{} `json:"-"`
}
type ScopePolicyOperators struct {
	Value   string                     `json:"value,omitempty"`
	Add     SliceOrSingleValue[string] `json:"add,omitempty"`
	Default []string                   `json:"default,omitempty"`

	Essential  bool     `json:"essential,omitempty"`
	SubsetOf   []string `json:"subset_of,omitempty"`
	SupersetOf []string `json:"superset_of,omitempty"`

	Extra map[string]interface{} `json:"-"`
}

type OpenIDRelyingPartyMetadata struct {
	Scope                                 string   `json:"scope,omitempty"`
	RedirectURIS                          []string `json:"redirect_uris,omitempty"`
	ResponseTypes                         []string `json:"response_types,omitempty"`
	GrantTypes                            []string `json:"grant_types,omitempty"`
	ApplicationType                       string   `json:"application_type,omitempty"`
	Contacts                              []string `json:"contacts,omitempty"`
	ClientName                            string   `json:"client_name,omitempty"`
	LogoURI                               string   `json:"logo_uri,omitempty"`
	ClientURI                             string   `json:"client_uri,omitempty"`
	PolicyURI                             string   `json:"policy_uri,omitempty"`
	TOSURI                                string   `json:"tos_uri,omitempty"`
	JWKSURI                               string   `json:"jwks_uri,omitempty"`
	JWKS                                  jwk.Set  `json:"jwks,omitempty"`
	SignedJWKSURI                         string   `json:"signed_jwks_uri,omitempty"`
	SectorIdentifierURI                   string   `json:"sector_identifier_uri,omitempty"`
	SubjectType                           string   `json:"subject_type,omitempty"`
	IDTokenSignedResponseAlg              string   `json:"id_token_signed_response_alg,omitempty"`
	IDTokenEncryptedResponseAlg           string   `json:"id_token_encrypted_response_alg,omitempty"`
	IDTokenEncryptedResponseEnc           string   `json:"id_token_encrypted_response_enc,omitempty"`
	UserinfoSignedResponseAlg             string   `json:"userinfo_signed_response_alg,omitempty"`
	UserinfoEncryptedResponseAlg          string   `json:"userinfo_encrypted_response_alg,omitempty"`
	UserinfoEncryptedResponseEnc          string   `json:"userinfo_encrypted_response_enc,omitempty"`
	RequestSignedResponseAlg              string   `json:"request_signed_response_alg,omitempty"`
	RequestEncryptedResponseAlg           string   `json:"request_encrypted_response_alg,omitempty"`
	RequestEncryptedResponseEnc           string   `json:"request_encrypted_response_enc,omitempty"`
	TokenEndpointAuthMethod               string   `json:"token_endpoint_auth_method,omitempty"`
	TokenEndpointAuthSigningAlg           string   `json:"token_endpoint_auth_signing_alg,omitempty"`
	DefaultMaxAge                         int64    `json:"default_max_age,omitempty"`
	RequireAuthTime                       bool     `json:"require_auth_time,omitempty"`
	DefaultACRValues                      []string `json:"default_acr_values,omitempty"`
	InitiateLoginURI                      string   `json:"initiate_login_uri,omitempty"`
	RequestURIs                           []string `json:"request_uris,omitempty"`
	SoftwareID                            string   `json:"software_id,omitempty"`
	SoftwareVersion                       string   `json:"software_version,omitempty"`
	ClientID                              string   `json:"client_id,omitempty"`
	ClientSecret                          string   `json:"client_secret,omitempty"`
	ClientIDIssuedAt                      int64    `json:"client_id_issued_at,omitempty"`
	ClientSecretExpiresAt                 int64    `json:"client_secret_expires_at,omitempty"`
	RegistrationAccessToken               string   `json:"registration_access_token,omitempty"`
	RegistrationClientURI                 string   `json:"registration_client_uri,omitempty"`
	ClaimsRedirectURIs                    []string `json:"claims_redirect_uris,omitempty"`
	NFVTokenSignedResponseAlg             string   `json:"nfv_token_signed_response_alg,omitempty"`
	NFVTokenEncryptedResponseAlg          string   `json:"nfv_token_encrypted_response_alg,omitempty"`
	NFVTokenEncryptedResponseEnc          string   `json:"nfv_token_encrypted_response_enc,omitempty"`
	TLSClientCertificateBoundAccessTokens bool     `json:"tls_client_certificate_bound_access_tokens,omitempty"`
	TLSClientAuthSubjectDN                string   `json:"tls_client_auth_subject_dn,omitempty"`
	TLSClientAuthSANDNS                   string   `json:"tls_client_auth_san_dns,omitempty"`
	TLSClientAuthSANURI                   string   `json:"tls_client_auth_san_uri,omitempty"`
	TLSClientAuthSANIP                    string   `json:"tls_client_auth_san_ip,omitempty"`
	TLSClientAuthSANEMAIL                 string   `json:"tls_client_auth_san_email,omitempty"`
	RequireSignedRequestObject            bool     `json:"require_signed_request_object,omitempty"`
	RequirePushedAuthorizationRequests    bool     `json:"require_pushed_authorization_requests,omitempty"`
	IntrospectionSignedResponseAlg        string   `json:"introspection_signed_response_alg,omitempty"`
	IntrospectionEncryptedResponseAlg     string   `json:"introspection_encrypted_response_alg,omitempty"`
	IntrospectionEncryptedResponseEnc     string   `json:"introspection_encrypted_response_enc,omitempty"`
	FrontchannelLogoutURI                 string   `json:"frontchannel_logout_uri,omitempty"`
	FrontchannelLogoutSessionRequired     bool     `json:"frontchannel_logout_session_required,omitempty"`
	BackchannelLogoutURI                  string   `json:"backchannel_logout_uri,omitempty"`
	BackchannelLogoutSessionRequired      bool     `json:"backchannel_logout_session_required,omitempty"`
	PostLogoutRedirectURIs                []string `json:"post_logout_redirect_uris,omitempty"`
	AuthorizationDetailsTypes             []string `json:"authorization_details_types,omitempty"`
	OrganizationName                      string   `json:"organization_name,omitempty"`
	ClientRegistrationTypes               []string `json:"client_registration_types"`

	Extra map[string]interface{} `json:"-"`
}

type OpenIDRelyingPartyMetadataPolicy struct {
	Scope                                 ScopePolicyOperators            `json:"scope,omitempty"`
	RedirectURIS                          PolicyOperatorsSliced[[]string] `json:"redirect_uris,omitempty"`
	ResponseTypes                         PolicyOperatorsSliced[[]string] `json:"response_types,omitempty"`
	GrantTypes                            PolicyOperatorsSliced[[]string] `json:"grant_types,omitempty"`
	ApplicationType                       PolicyOperators[string]         `json:"application_type,omitempty"`
	Contacts                              PolicyOperatorsSliced[[]string] `json:"contacts,omitempty"`
	ClientName                            PolicyOperators[string]         `json:"client_name,omitempty"`
	LogoURI                               PolicyOperators[string]         `json:"logo_uri,omitempty"`
	ClientURI                             PolicyOperators[string]         `json:"client_uri,omitempty"`
	PolicyURI                             PolicyOperators[string]         `json:"policy_uri,omitempty"`
	TOSURI                                PolicyOperators[string]         `json:"tos_uri,omitempty"`
	JWKSURI                               PolicyOperators[string]         `json:"jwks_uri,omitempty"`
	JWKS                                  JWKSPolicyOperators             `json:"jwks,omitempty"`
	SignedJWKSURI                         PolicyOperators[string]         `json:"signed_jwks_uri,omitempty"`
	SectorIdentifierURI                   PolicyOperators[string]         `json:"sector_identifier_uri,omitempty"`
	SubjectType                           PolicyOperators[string]         `json:"subject_type,omitempty"`
	IDTokenSignedResponseAlg              PolicyOperators[string]         `json:"id_token_signed_response_alg,omitempty"`
	IDTokenEncryptedResponseAlg           PolicyOperators[string]         `json:"id_token_encrypted_response_alg,omitempty"`
	IDTokenEncryptedResponseEnc           PolicyOperators[string]         `json:"id_token_encrypted_response_enc,omitempty"`
	UserinfoSignedResponseAlg             PolicyOperators[string]         `json:"userinfo_signed_response_alg,omitempty"`
	UserinfoEncryptedResponseAlg          PolicyOperators[string]         `json:"userinfo_encrypted_response_alg,omitempty"`
	UserinfoEncryptedResponseEnc          PolicyOperators[string]         `json:"userinfo_encrypted_response_enc,omitempty"`
	RequestSignedResponseAlg              PolicyOperators[string]         `json:"request_signed_response_alg,omitempty"`
	RequestEncryptedResponseAlg           PolicyOperators[string]         `json:"request_encrypted_response_alg,omitempty"`
	RequestEncryptedResponseEnc           PolicyOperators[string]         `json:"request_encrypted_response_enc,omitempty"`
	TokenEndpointAuthMethod               PolicyOperators[string]         `json:"token_endpoint_auth_method,omitempty"`
	TokenEndpointAuthSigningAlg           PolicyOperators[string]         `json:"token_endpoint_auth_signing_alg,omitempty"`
	DefaultMaxAge                         PolicyOperators[int64]          `json:"default_max_age,omitempty"`
	RequireAuthTime                       PolicyOperators[bool]           `json:"require_auth_time,omitempty"`
	DefaultACRValues                      PolicyOperatorsSliced[[]string] `json:"default_acr_values,omitempty"`
	InitiateLoginURI                      PolicyOperators[string]         `json:"initiate_login_uri,omitempty"`
	RequestURIs                           PolicyOperatorsSliced[[]string] `json:"request_uris,omitempty"`
	SoftwareID                            PolicyOperators[string]         `json:"software_id,omitempty"`
	SoftwareVersion                       PolicyOperators[string]         `json:"software_version,omitempty"`
	ClientID                              PolicyOperators[string]         `json:"client_id,omitempty"`
	ClientSecret                          PolicyOperators[string]         `json:"client_secret,omitempty"`
	ClientIDIssuedAt                      PolicyOperators[int64]          `json:"client_id_issued_at,omitempty"`
	ClientSecretExpiresAt                 PolicyOperators[int64]          `json:"client_secret_expires_at,omitempty"`
	RegistrationAccessToken               PolicyOperators[string]         `json:"registration_access_token,omitempty"`
	RegistrationClientURI                 PolicyOperators[string]         `json:"registration_client_uri,omitempty"`
	ClaimsRedirectURIs                    PolicyOperatorsSliced[[]string] `json:"claims_redirect_uris,omitempty"`
	NFVTokenSignedResponseAlg             PolicyOperators[string]         `json:"nfv_token_signed_response_alg,omitempty"`
	NFVTokenEncryptedResponseAlg          PolicyOperators[string]         `json:"nfv_token_encrypted_response_alg,omitempty"`
	NFVTokenEncryptedResponseEnc          PolicyOperators[string]         `json:"nfv_token_encrypted_response_enc,omitempty"`
	TLSClientCertificateBoundAccessTokens PolicyOperators[bool]           `json:"tls_client_certificate_bound_access_tokens,omitempty"`
	TLSClientAuthSubjectDN                PolicyOperators[string]         `json:"tls_client_auth_subject_dn,omitempty"`
	TLSClientAuthSANDNS                   PolicyOperators[string]         `json:"tls_client_auth_san_dns,omitempty"`
	TLSClientAuthSANURI                   PolicyOperators[string]         `json:"tls_client_auth_san_uri,omitempty"`
	TLSClientAuthSANIP                    PolicyOperators[string]         `json:"tls_client_auth_san_ip,omitempty"`
	TLSClientAuthSANEMAIL                 PolicyOperators[string]         `json:"tls_client_auth_san_email,omitempty"`
	RequireSignedRequestObject            PolicyOperators[bool]           `json:"require_signed_request_object,omitemty"`
	RequirePushedAuthorizationRequests    PolicyOperators[bool]           `json:"require_pushed_authorization_request,omitempty"`
	IntrospectionSignedResponseAlg        PolicyOperators[string]         `json:"introspection_signed_response_alg,omitempty"`
	IntrospectionEncryptedResponseAlg     PolicyOperators[string]         `json:"introspection_encrypted_response_alg,omitempty"`
	IntrospectionEncryptedResponseEnc     PolicyOperators[string]         `json:"introspection_encrypted_response_enc,omitempty"`
	FrontchannelLogoutURI                 PolicyOperators[string]         `json:"frontchannel_logout_uri,omitempty"`
	FrontchannelLogoutSessionRequired     PolicyOperators[bool]           `json:"frontchannel_logout_session_required,omitempty"`
	BackchannelLogoutURI                  PolicyOperators[string]         `json:"backchannel_logout_uri,omitempty"`
	BackchannelLogoutSessionRequired      PolicyOperators[bool]           `json:"backchannel_logout_session_required,omitempty"`
	PostLogoutRedirectURIs                PolicyOperatorsSliced[[]string] `json:"post_logout_redirect_uris,omitempty"`
	AuthorizationDetailsTypes             PolicyOperatorsSliced[[]string] `json:"authorization_details_types,omitempty"`
	OrganizationName                      PolicyOperators[string]         `json:"organization_name,omitempty"`
	ClientRegistrationTypes               PolicyOperatorsSliced[[]string] `json:"client_registration_types"`

	Extra map[string]interface{} `json:"-"`
}

type OpenIDProviderMetadata struct {
	Issuer                                                    string              `json:"issuer"`
	AuthorizationEndpoint                                     string              `json:"authorization_endpoint"`
	TokenEndpoint                                             string              `json:"token_endpoint"`
	UserinfoEndpoint                                          string              `json:"userinfo_endpoint,omitempty"`
	JWKSURI                                                   string              `json:"jwks_uri,omitempty"`
	JWKS                                                      jwk.Set             `json:"jwks,omitempty"`
	SignedJWKSURI                                             string              `json:"signed_jwks_uri,omitempty"`
	RegistrationEndpoint                                      string              `json:"registration_endpoint,omitempty"`
	ScopesSupported                                           []string            `json:"scopes_supported,omitempty"`
	ResponseTypesSupported                                    []string            `json:"response_types_supported"`
	ResponseModesSupported                                    []string            `json:"response_modes_supported,omitempty"`
	GrantTypesSupported                                       []string            `json:"grant_types_supported,omitempty"`
	ACRValuesSupported                                        []string            `json:"acr_values_supported,omitempty"`
	SubjectTypesSupported                                     []string            `json:"subject_types_supported"`
	IDTokenSignedResponseAlgValuesSupported                   []string            `json:"id_token_signed_response_alg_values_supported,omitempty"`
	IDTokenEncryptedResponseAlgValuesSupported                []string            `json:"id_token_encrypted_response_alg_values_supported,omitempty"`
	IDTokenEncryptedResponseEncValuesSupported                []string            `json:"id_token_encrypted_response_enc_values_supported,omitempty"`
	UserinfoSignedResponseAlgValuesSupported                  []string            `json:"userinfo_signed_response_alg_values_supported,omitempty"`
	UserinfoEncryptedResponseAlgValuesSupported               []string            `json:"userinfo_encrypted_response_alg_values_supported,omitempty"`
	UserinfoEncryptedResponseEncValuesSupported               []string            `json:"userinfo_encrypted_response_enc_values_supported,omitempty"`
	RequestSignedResponseAlgValuesSupported                   []string            `json:"request_signed_response_alg_values_supported,omitempty"`
	RequestEncryptedResponseAlgValuesSupported                []string            `json:"request_encrypted_response_alg_values_supported,omitempty"`
	RequestEncryptedResponseEncValuesSupported                []string            `json:"request_encrypted_response_enc_values_supported,omitempty"`
	TokenEndpointAuthMethodsSupported                         []string            `json:"token_endpoint_auth_methods_supported,omitempty"`
	TokenEndpointAuthSigningAlgValuesSupported                []string            `json:"token_endpoint_auth_signing_alg_values_supported,omitempty"`
	DisplayValuesSupported                                    []string            `json:"display_values_supported,omitempty"`
	ClaimsSupported                                           []string            `json:"claims_supported,omitempty"`
	ServiceDocumentation                                      string              `json:"service_documentation,omitempty"`
	ClaimsLocalesSupported                                    []string            `json:"claims_locales_supported,omitempty"`
	UILocalesSupported                                        []string            `json:"ui_locales_supported,omitempty"`
	ClaimsParameterSupported                                  bool                `json:"claims_parameter_supported,omitempty"`
	RequestParameterSupported                                 bool                `json:"request_parameter_supported,omitempty"`
	RequestURIParameterSupported                              bool                `json:"request_uri_parameter_supported"`
	RequireRequestURIRegistration                             bool                `json:"require_request_uri_registration,omitempty"`
	OPPolicyURI                                               string              `json:"op_policy_uri,omitempty"`
	OPTOSURI                                                  string              `json:"op_tos_uri,omitempty"`
	RevocationEndpoint                                        string              `json:"revocation_endpoint,omitempty"`
	RevocationEndpointAuthMethodsSupported                    []string            `json:"revocation_endpoint_auth_methods_supported,omitempty"`
	RevocationEndpointAuthSigningAlgValuesSupported           []string            `json:"revocation_endpoint_auth_signing_alg_values_supported,omitempty"`
	IntrospectionEndpoint                                     string              `json:"introspection_endpoint,omitempty"`
	IntrospectionEndpointAuthMethodsSupported                 []string            `json:"introspection_endpoint_auth_methods_supported,omitempty"`
	IntrospectionEndpointAuthSigningAlgValuesSupported        []string            `json:"introspection_endpoint_auth_signing_alg_values_supported,omitempty"`
	IntrospectionSigningAlgValuesSupported                    []string            `json:"introspection_signing_alg_values_supported,omitempty"`
	IntrospectionEncryptionAlgValuesSupported                 []string            `json:"introspection_encryption_alg_values_supported,omitempty"`
	IntrospectionEncryptionEncValuesSupported                 []string            `json:"introspection_encryption_enc_values_supported,omitempty"`
	CodeChallengeMethodsSupported                             []string            `json:"code_challenge_methods_supported,omitempty"`
	SignedMetadata                                            string              `json:"signed_metadata,omitempty"`
	DeviceAuthorizationEndpoint                               string              `json:"device_authorization_endpoint,omitempty"`
	TLSClientCertificateBoundAccessTokens                     bool                `json:"tls_client_certificate_bound_access_tokens,omitempty"`
	MTLSEndpointAliases                                       map[string]string   `json:"mtls_endpoint_aliases,omitempty"`
	NFVTokenSigningAlgValuesSupported                         []string            `json:"nfv_token_signing_alg_values_supported,omitempty"`
	NFVTokenEncryptionAlgValuesSupported                      []string            `json:"nfv_token_encryption_alg_values_supported,omitempty"`
	NFVTokenEncryptionEncValuesSupported                      []string            `json:"nfv_token_encryption_enc_values_supported,omitempty"`
	RequireSignedRequestObject                                bool                `json:"require_signed_request_object,omitempty"`
	PushedAuthorizationRequestEndpoint                        string              `json:"pushed_authorization_request_endpoint,omitempty"`
	RequirePushedAuthorizationRequests                        bool                `json:"require_pushed_authorization_requests,omitempty"`
	AuthorizationResponseIssParameterSupported                bool                `json:"authorization_response_iss_parameter_supported,omitempty"`
	CheckSessionIFrame                                        string              `json:"check_session_iframe,omitempty"`
	FrontchannelLogoutSupported                               bool                `json:"frontchannel_logout_supported,omitempty"`
	BackchannelLogoutSupported                                bool                `json:"backchannel_logout_supported,omitempty"`
	BackchannelLogoutSessionSupported                         bool                `json:"backchannel_logout_session_supported,omitempty"`
	EndSessionEndpoint                                        string              `json:"end_session_endpoint,omitempty"`
	BackchannelTokenDeliveryModesSupported                    []string            `json:"backchannel_token_delivery_modes_supported,omitempty"`
	BackchannelAuthenticationEndpoint                         string              `json:"backchannel_authentication_endpoint,omitempty"`
	BackchannelAuthenticationRequestSigningAlgValuesSupported []string            `json:"backchannel_authentication_request_signing_alg_values_supported,omitempty"`
	BackchannelUserCodeParameterSupported                     bool                `json:"backchannel_user_code_parameter_supported,omitempty"`
	AuthorizationDetailsTypesSupported                        []string            `json:"authorization_details_types_supported,omitempty"`
	ClientRegistrationTypesSupported                          []string            `json:"client_registration_types_supported"`
	FederationRegistrationEndpoint                            string              `json:"federation_registration_endpoint,omitempty"`
	RequestAuthenticationMethodsSupported                     map[string][]string `json:"request_authentication_methods_supported,omitempty"`
	RequestAuthenticationSigningAlgValuesSupported            []string            `json:"request_authentication_signing_alg_values_supported,omitempty"`
	OrganizationName                                          string              `json:"organization_name,omitempty"`

	Extra map[string]interface{} `json:"-"`
}

type OpenIDProviderMetadataPolicy struct {
	Issuer                                                    PolicyOperators[string]         `json:"issuer"`
	AuthorizationEndpoint                                     PolicyOperators[string]         `json:"authorization_endpoint"`
	TokenEndpoint                                             PolicyOperators[string]         `json:"token_endpoint"`
	UserinfoEndpoint                                          PolicyOperators[string]         `json:"userinfo_endpoint,omitempty"`
	JWKSURI                                                   PolicyOperators[string]         `json:"jwks_uri,omitempty"`
	JWKS                                                      JWKSPolicyOperators             `json:"jwks,omitempty"`
	SignedJWKSURI                                             PolicyOperators[string]         `json:"signed_jwks_uri,omitempty"`
	RegistrationEndpoint                                      PolicyOperators[string]         `json:"registration_endpoint,omitempty"`
	ScopesSupported                                           PolicyOperatorsSliced[[]string] `json:"scopes_supported,omitempty"`
	ResponseTypesSupported                                    PolicyOperatorsSliced[[]string] `json:"response_types_supported"`
	ResponseModesSupported                                    PolicyOperatorsSliced[[]string] `json:"response_modes_supported,omitempty"`
	GrantTypesSupported                                       PolicyOperatorsSliced[[]string] `json:"grant_types_supported,omitempty"`
	ACRValuesSupported                                        PolicyOperatorsSliced[[]string] `json:"acr_values_supported,oitempty"`
	SubjectTypesSupported                                     PolicyOperatorsSliced[[]string] `json:"subject_types_supporte"`
	IDTokenSignedResponseAlgValuesSupported                   PolicyOperatorsSliced[[]string] `json:"id_token_signed_respone_alg_values_supported,omitempty"`
	IDTokenEncryptedResponseAlgValuesSupported                PolicyOperatorsSliced[[]string] `json:"id_token_encrypted_resonse_alg_values_supported,omitempty"`
	IDTokenEncryptedResponseEncValuesSupported                PolicyOperatorsSliced[[]string] `json:"id_token_encrypted_resonse_enc_values_supported,omitempty"`
	UserinfoSignedResponseAlgValuesSupported                  PolicyOperatorsSliced[[]string] `json:"userinfo_signed_respons_alg_values_supported,omitempty"`
	UserinfoEncryptedResponseAlgValuesSupported               PolicyOperatorsSliced[[]string] `json:"userinfo_encrypted_respnse_alg_values_supported,omitempty"`
	UserinfoEncryptedResponseEncValuesSupported               PolicyOperatorsSliced[[]string] `json:"userinfo_encrypted_respnse_enc_values_supported,omitempty"`
	RequestSignedResponseAlgValuesSupported                   PolicyOperatorsSliced[[]string] `json:"request_signed_responsealg_values_supported,omitempty"`
	RequestEncryptedResponseAlgValuesSupported                PolicyOperatorsSliced[[]string] `json:"request_encrypted_respose_alg_values_supported,omitempty"`
	RequestEncryptedResponseEncValuesSupported                PolicyOperatorsSliced[[]string] `json:"request_encrypted_respone_enc_values_supported,omitempty"`
	TokenEndpointAuthMethodsSupported                         PolicyOperatorsSliced[[]string] `json:"token_endpoint_auth_methds_supported,omitempty"`
	TokenEndpointAuthSigningAlgValuesSupported                PolicyOperatorsSliced[[]string] `json:"token_endpoint_auth_signng_alg_values_supported,omitempty"`
	DisplayValuesSupported                                    PolicyOperatorsSliced[[]string] `json:"display_values_supportedomitempty"`
	ClaimsSupported                                           PolicyOperatorsSliced[[]string] `json:"claims_supported,omitempy"`
	ServiceDocumentation                                      PolicyOperators[string]         `json:"service_documentation,omitempty"`
	ClaimsLocalesSupported                                    PolicyOperatorsSliced[[]string] `json:"claims_locales_supported,omitempty"`
	UILocalesSupported                                        PolicyOperatorsSliced[[]string] `json:"ui_locales_supported,omitempty"`
	ClaimsParameterSupported                                  PolicyOperators[bool]           `json:"claims_parameter_supported,omitempty"`
	RequestParameterSupported                                 PolicyOperators[bool]           `json:"request_parameter_supported,omitempty"`
	RequestURIParameterSupported                              PolicyOperators[bool]           `json:"request_uri_parameter_supported"`
	RequireRequestURIRegistration                             PolicyOperators[bool]           `json:"require_request_uri_registration,omitempty"`
	OPPolicyURI                                               PolicyOperators[string]         `json:"op_policy_uri,omitempty"`
	OPTOSURI                                                  PolicyOperators[string]         `json:"op_tos_uri,omitempty"`
	RevocationEndpoint                                        PolicyOperators[string]         `json:"revocation_endpoint,omitempty"`
	RevocationEndpointAuthMethodsSupported                    PolicyOperatorsSliced[[]string] `json:"revocation_endpoint_auth_methods_supported,omitempty"`
	RevocationEndpointAuthSigningAlgValuesSupported           PolicyOperatorsSliced[[]string] `json:"evocation_endpoint_auth_signing_alg_values_supported,omitempty"`
	IntrospectionEndpoint                                     PolicyOperators[string]         `json:"introspection_endpoint,omitempty"`
	IntrospectionEndpointAuthMethodsSupported                 PolicyOperatorsSliced[[]string] `json:"ntrospection_endpoint_auth_methods_supported,omitempty"`
	IntrospectionEndpointAuthSigningAlgValuesSupported        PolicyOperatorsSliced[[]string] `json:"ntrospection_endpoint_auth_signing_alg_values_supported,omitempty"`
	IntrospectionSigningAlgValuesSupported                    PolicyOperatorsSliced[[]string] `json:"ntrospection_signing_alg_values_supported,omitempty"`
	IntrospectionEncryptionAlgValuesSupported                 PolicyOperatorsSliced[[]string] `json:"ntrospection_encryption_alg_values_supported,omitempty"`
	IntrospectionEncryptionEncValuesSupported                 PolicyOperatorsSliced[[]string] `json:"ntrospection_encryption_enc_values_supported,omitempty"`
	CodeChallengeMethodsSupported                             PolicyOperatorsSliced[[]string] `json:"ode_challenge_methods_supported,omitempty"`
	SignedMetadata                                            PolicyOperators[string]         `json:"signed_metadata,omitempty"`
	DeviceAuthorizationEndpoint                               PolicyOperators[string]         `json:"device_authorization_endpoint,omitempty"`
	TLSClientCertificateBoundAccessTokens                     PolicyOperators[bool]           `json:"tls_client_certificate_bound_access_tokens,omitempty"`
	MTLSEndpointAliases                                       map[string]interface{}          `json:"mtls_endpoint_aliases,omitempty"`
	NFVTokenSigningAlgValuesSupported                         PolicyOperatorsSliced[[]string] `json:"nfv_token_signing_alg_values_supported,omitempty"`
	NFVTokenEncryptionAlgValuesSupported                      PolicyOperatorsSliced[[]string] `json:"fv_token_encryption_alg_values_supported,omitempty"`
	NFVTokenEncryptionEncValuesSupported                      PolicyOperatorsSliced[[]string] `json:"nfv_token_encryption_enc_values_supported,omitempty"`
	RequireSignedRequestObject                                PolicyOperators[bool]           `json:"require_signed_request_object,omitempty"`
	PushedAuthorizationRequestEndpoint                        PolicyOperators[string]         `json:"pushed_authorization_request_endpoint,omitempty"`
	RequirePushedAuthorizationRequests                        PolicyOperators[bool]           `json:"require_pushed_authorization_requests,omitempty"`
	AuthorizationResponseIssParameterSupported                PolicyOperators[bool]           `json:"authorization_response_iss_parameter_supported,omitempty"`
	CheckSessionIFrame                                        PolicyOperators[string]         `json:"check_session_iframe,omitempty"`
	FrontchannelLogoutSupported                               PolicyOperators[bool]           `json:"frontchannel_logout_supported,omitempty"`
	BackchannelLogoutSupported                                PolicyOperators[bool]           `json:"backchannel_logout_supported,omitempty"`
	BackchannelLogoutSessionSupported                         PolicyOperators[bool]           `json:"backchannel_logout_session_supported,omitempty"`
	EndSessionEndpoint                                        PolicyOperators[string]         `json:"end_session_endpoint,omitempty"`
	BackchannelTokenDeliveryModesSupported                    PolicyOperatorsSliced[[]string] `json:"backchannel_token_delivery_modes_supported,omitempty"`
	BackchannelAuthenticationEndpoint                         PolicyOperators[string]         `json:"backchannel_authentication_endpoint,omitempty"`
	BackchannelAuthenticationRequestSigningAlgValuesSupported PolicyOperatorsSliced[[]string] `json:"backchannel_authentication_request_signing_alg_values_supported,omitempty"`
	BackchannelUserCodeParameterSupported                     PolicyOperators[bool]           `json:"backchannel_user_code_parameter_supported,omitempty"`
	AuthorizationDetailsTypesSupported                        PolicyOperatorsSliced[[]string] `json:"authorization_details_types_supported,omitempty"`
	ClientRegistrationTypesSupported                          PolicyOperatorsSliced[[]string] `json:"client_registration_types_supported"`
	FederationRegistrationEndpoint                            PolicyOperators[string]         `json:"federation_registration_endpoint,omitempty"`
	RequestAuthenticationMethodsSupported                     map[string]interface{}          `json:"request_authentication_methods_supported,omitempty"`
	RequestAuthenticationSigningAlgValuesSupported            PolicyOperatorsSliced[[]string] `json:"equest_authentication_signing_alg_values_supported,omitempty"`
	OrganizationName                                          PolicyOperators[string]         `json:"organization_name,omitempty"`

	Extra map[string]interface{} `json:"-"`
}

type OAuthClientMetadata OpenIDRelyingPartyMetadata
type OAuthClientMetadataPolicy OpenIDRelyingPartyMetadataPolicy

type OAuthAuthorizationServerMetadata OpenIDProviderMetadata
type OAuthAuthorizationServerMetadataPolicy OpenIDProviderMetadataPolicy

type OAuthProtectedResourceMetadata struct {
	Resource                             string   `json:"resource,omitempty"`
	AuthorizationServers                 []string `json:"authorization_servers,omitempty"`
	ScopesProvided                       []string `json:"scopes_provided,omitempty"`
	BearerMethodsSupported               []string `json:"bearer_methods_supported,omitempty"`
	ResourceSigningAlgValuesSupported    []string `json:"resource_signing_alg_values_supported,omitempty"`
	ResourceEncryptionAlgValuesSupported []string `json:"resource_encryption_alg_values_supported"`
	ResourceEncryptionEncValuesSupported []string `json:"resource_encryption_enc_values_supported"`
	ResourceDocumentation                string   `json:"resource_documentation,omitempty"`
	ResourcePolicyURI                    string   `json:"resource_policy_uri,omitempty"`
	ResourceTOSURI                       string   `json:"resource_tos_uri,omitempty"`

	JWKSURI          string  `json:"jwks_uri,omitempty"`
	JWKS             jwk.Set `json:"jwks,omitempty"`
	SignedJWKSURI    string  `json:"signed_jwks_uri,omitempty"`
	OrganizationName string  `json:"organization_name,omitempty"`

	Extra map[string]interface{} `json:"-"`
}

type OAuthProtectedResourceMetadataPolicy struct {
	Resource                             PolicyOperators[string]         `json:"resource,omitempty"`
	AuthorizationServers                 PolicyOperatorsSliced[[]string] `json:"authorization_servers,omitempty"`
	ScopesProvided                       PolicyOperatorsSliced[[]string] `json:"scopes_provided,omitempty"`
	BearerMethodsSupported               PolicyOperatorsSliced[[]string] `json:"bearer_methods_supported,omitempty"`
	ResourceSigningAlgValuesSupported    PolicyOperatorsSliced[[]string] `json:"resource_signing_alg_values_supported,omitempty"`
	ResourceEncryptionAlgValuesSupported PolicyOperatorsSliced[[]string] `json:"resource_encryption_alg_values_supported"`
	ResourceEncryptionEncValuesSupported PolicyOperatorsSliced[[]string] `json:"resource_encryption_enc_values_supported"`
	ResourceDocumentation                PolicyOperators[string]         `json:"resource_documentation,omitempty"`
	ResourcePolicyURI                    PolicyOperators[string]         `json:"resource_policy_uri,omitempty"`
	ResourceTOSURI                       PolicyOperators[string]         `json:"resource_tos_uri,omitempty"`
	JWKSURI                              PolicyOperators[string]         `json:"jwks_uri,omitempty"`
	JWKS                                 JWKSPolicyOperators             `json:"jwks,omitempty"`
	SignedJWKSURI                        PolicyOperators[string]         `json:"signed_jwks_uri,omitempty"`
	OrganizationName                     PolicyOperators[string]         `json:"organization_name,omitempty"`

	Extra map[string]interface{} `json:"-"`
}

type FederationEntityMetadata struct {
	FederationFetchEndpoint           string `json:"federation_fetch_endpoint,omitempty"`
	FederationListEndpoint            string `json:"federation_list_endpoint,omitempty"`
	FederationResolveEndpoint         string `json:"federation_resolve_endpoint,omitempty"`
	FederationTrustMarkStatusEndpoint string `json:"federation_trust_mark_status_endpoint,omitempty"`

	OrganizationName string   `json:"organization_name,omitempty"`
	Contacts         []string `json:"contacts,omitempty"`
	LogoURI          string   `json:"logo_uri,omitempty"`
	PolicyURI        string   `json:"policy_uri,omitempty"`
	HomepageURI      string   `json:"homepage_uri,omitempty"`
}

type FederationEntityMetadataPolicy struct {
	FederationFetchEndpoint           PolicyOperators[string] `json:"federation_fetch_endpoint,omitempty"`
	FederationListEndpoint            PolicyOperators[string] `json:"federation_list_endpoint,omitempty"`
	FederationResolveEndpoint         PolicyOperators[string] `json:"federation_resolve_endpoint,omitempty"`
	FederationTrustMarkStatusEndpoint PolicyOperators[string] `json:"federation_trust_mark_status_endpoint,omitempty"`

	OrganizationName PolicyOperators[string]         `json:"organization_name,omitempty"`
	Contacts         PolicyOperatorsSliced[[]string] `json:"contacts,omitempty"`
	LogoURI          PolicyOperators[string]         `json:"logo_uri,omitempty"`
	PolicyURI        PolicyOperators[string]         `json:"policy_uri,omitempty"`
	HomepageURI      PolicyOperators[string]         `json:"homepage_uri,omitempty"`
}

type ConstraintSpecification struct {
	MaxPathLength          int               `json:"max_path_length,omitempty"`
	NamingConstraints      NamingConstraints `json:"naming_constraints,omitempty"`
	AllowedLeafEntityTypes []string          `json:"allowed_leaf_entity_types,omitempty"`
}

type NamingConstraints struct {
	Permitted []string `json:"permitted,omitempty"`
	Excluded  []string `json:"excluded,omitempty"`
}

type AllowedTrustMarkIssuers map[string][]string

func (entity EntityStatement) JWT() ([]byte, error) {
	if key == nil {
		return nil, errors.New("no signing key set")
	}
	j, err := json.Marshal(entity)
	if err != nil {
		return nil, err
	}
	return sign(j)
}
