package constants

const (
	ContentTypeEntityStatement = "application/entity-statement+jwt"
	ContentTypeResolveResponse = "application/resolve-response+jwt"
	JWTTypeEntityStatement     = "entity-statement+jwt"
	JWTTypeTrustMarkDelegation = "trust-mark-delegation+jwt"
	JWTTypeTrustMark           = "trust-mark+jwt"
	JWTTypeResolveResponse     = "resolve-response+jwt"
)

const (
	EntityTypeFederationEntity       = "federation_entity"
	EntityTypeOpenIDRelyingParty     = "openid_relying_party"
	EntityTypeOpenIDProvider         = "openid_provider"
	EntityTypeOAuthClient            = "oauth_client"
	EntityTypeOAuthProtectedResource = "oauth_resource"
)
