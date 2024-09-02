package constants

// Constants for JWT Types
const (
	ContentTypeEntityStatement = "application/entity-statement+jwt"
	ContentTypeResolveResponse = "application/resolve-response+jwt"
	JWTTypeEntityStatement     = "entity-statement+jwt"
	JWTTypeTrustMarkDelegation = "trust-mark-delegation+jwt"
	JWTTypeTrustMark           = "trust-mark+jwt"
	JWTTypeResolveResponse     = "resolve-response+jwt"
)

// Constants for entity types
const (
	EntityTypeFederationEntity       = "federation_entity"
	EntityTypeOpenIDRelyingParty     = "openid_relying_party"
	EntityTypeOpenIDProvider         = "openid_provider"
	EntityTypeOAuthClient            = "oauth_client"
	EntityTypeOAuthProtectedResource = "oauth_resource"
)
