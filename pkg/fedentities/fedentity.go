package fedentities

import (
	"crypto"
	"net/http"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/adaptor"
	"github.com/gofiber/fiber/v2/middleware/compress"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/lestrrat-go/jwx/jwa"

	"github.com/zachmann/go-oidfed/internal/utils"
	"github.com/zachmann/go-oidfed/pkg"
	"github.com/zachmann/go-oidfed/pkg/cache"
	"github.com/zachmann/go-oidfed/pkg/constants"
	"github.com/zachmann/go-oidfed/pkg/fedentities/storage"
)

const (
	CacheKeyEntityConfiguration = "entity_configuration"
)

type EndpointConf struct {
	Internal string `yaml:"path"`
	External string `yaml:"url"`
}

func (c EndpointConf) Path() string {
	if c.Internal == "" {
		return c.External
	}
	return c.Internal
}
func (c EndpointConf) URL() string {
	if c.External == "" {
		return c.Internal
	}
	return c.External
}

type FedEntity struct {
	*pkg.FederationEntity
	*pkg.TrustMarkIssuer
	*pkg.GeneralJWTSigner
	SubordinateStatementsConfig
	server *fiber.App
}

type SubordinateStatementTypeConfig struct {
	SubordinateStatementLifetime int64
	Constraints                  *pkg.ConstraintSpecification
	CriticalExtensions           []string
	MetadataPolicyCrit           []pkg.PolicyOperatorName
	Extra                        map[string]any
}

type SubordinateStatementsConfig struct {
	MetadataPolicies *pkg.MetadataPolicies
	Configs          map[string]*SubordinateStatementTypeConfig
	resultingConfigs map[string]*SubordinateStatementTypeConfig
}

func (c *SubordinateStatementsConfig) Get(subordinateEntityType string) *SubordinateStatementTypeConfig {
	if c.resultingConfigs == nil {
		c.resultingConfigs = make(map[string]*SubordinateStatementTypeConfig)
	}
	if rs, ok := c.resultingConfigs[subordinateEntityType]; ok {
		return rs
	}
	rs := c.buildConfig(subordinateEntityType)
	c.resultingConfigs[subordinateEntityType] = rs
	return rs
}

func (c *SubordinateStatementsConfig) buildConfig(subordinateEntityType string) *SubordinateStatementTypeConfig {
	global, globalOK := c.Configs[""]
	forType, forTypeOK := c.Configs[subordinateEntityType]

	if !globalOK {
		return forType
	}

	rs := *global
	if forTypeOK {
		c.applyOverrides(&rs, forType)
	}

	return &rs
}

func (c *SubordinateStatementsConfig) applyOverrides(base, overrides *SubordinateStatementTypeConfig) {
	if overrides.SubordinateStatementLifetime != 0 {
		base.SubordinateStatementLifetime = overrides.SubordinateStatementLifetime
	}
	if overrides.CriticalExtensions != nil {
		base.CriticalExtensions = overrides.CriticalExtensions
	}
	if overrides.MetadataPolicyCrit != nil {
		base.MetadataPolicyCrit = overrides.MetadataPolicyCrit
	}
	if overrides.Extra != nil {
		base.Extra = overrides.Extra
	}
	c.applyConstraintsOverrides(base, overrides)
}

func (*SubordinateStatementsConfig) applyConstraintsOverrides(base, overrides *SubordinateStatementTypeConfig) {
	if overrides.Constraints == nil {
		return
	}
	if base.Constraints == nil {
		base.Constraints = overrides.Constraints
		return
	}

	if overrides.Constraints.NamingConstraints != nil {
		if base.Constraints.NamingConstraints == nil {
			base.Constraints.NamingConstraints = overrides.Constraints.NamingConstraints
		} else {
			if overrides.Constraints.NamingConstraints.Permitted != nil {
				base.Constraints.NamingConstraints.Permitted = overrides.Constraints.NamingConstraints.Permitted
			}
			if overrides.Constraints.NamingConstraints.Excluded != nil {
				base.Constraints.NamingConstraints.Excluded = overrides.Constraints.NamingConstraints.Excluded
			}
		}
	}

	if overrides.Constraints.AllowedLeafEntityTypes != nil {
		base.Constraints.AllowedLeafEntityTypes = overrides.Constraints.AllowedLeafEntityTypes
	}
	if overrides.Constraints.MaxPathLength != 0 {
		base.Constraints.MaxPathLength = overrides.Constraints.MaxPathLength
	}
}

func NewFedEntity(
	entityID string, authorityHints []string, metadata *pkg.Metadata,
	privateSigningKey crypto.Signer, signingAlg jwa.SignatureAlgorithm, configurationLifetime int64,
	stmtConfig SubordinateStatementsConfig,
) (
	*FedEntity,
	error,
) {
	generalSigner := pkg.NewGeneralJWTSigner(privateSigningKey, signingAlg)
	fed, err := pkg.NewFederationEntity(
		entityID, authorityHints, metadata, generalSigner.EntityStatementSigner(), configurationLifetime,
	)
	if err != nil {
		return nil, err
	}
	if fed.Metadata == nil {
		fed.Metadata = &pkg.Metadata{}
	}
	if fed.Metadata.FederationEntity == nil {
		fed.Metadata.FederationEntity = &pkg.FederationEntityMetadata{}
	}
	server := fiber.New()
	server.Use(recover.New())
	server.Use(compress.New())
	server.Use(logger.New())
	//TODO middleware configurable?
	entity := &FedEntity{
		FederationEntity:            fed,
		TrustMarkIssuer:             pkg.NewTrustMarkIssuer(entityID, generalSigner.TrustMarkSigner(), nil),
		GeneralJWTSigner:            generalSigner,
		SubordinateStatementsConfig: stmtConfig,
		server:                      server,
	}
	server.Get(
		"/.well-known/openid-federation", func(ctx *fiber.Ctx) error {
			cacheKey := cache.Key(CacheKeyEntityConfiguration, entityID)
			if cached, set := cache.Get(cacheKey); set {
				ctx.Set(fiber.HeaderContentType, constants.ContentTypeEntityStatement)
				jwt, ok := cached.([]byte)
				if ok {
					return ctx.Send(jwt)
				}
			}
			jwt, err := entity.EntityConfigurationJWT()
			if err != nil {
				return ctx.Status(fiber.StatusInternalServerError).JSON(pkg.ErrorServerError(err.Error()))
			}
			cache.Set(cacheKey, jwt, time.Duration(entity.ConfigurationLifetime/2))
			ctx.Set(fiber.HeaderContentType, constants.ContentTypeEntityStatement)
			return ctx.Send(jwt)
		},
	)
	return entity, nil
}

func (fed FedEntity) HttpHandlerFunc() http.HandlerFunc {
	return adaptor.FiberApp(fed.server)
}

func (fed FedEntity) Listen(addr string) error {
	return fed.server.Listen(addr)
}

func (fed FedEntity) CreateSubordinateStatement(subordinate *storage.SubordinateInfo) pkg.EntityStatementPayload {
	now := time.Now()
	subordinateStmtConfig := fed.SubordinateStatementsConfig.Get(subordinate.EntityType)
	return pkg.EntityStatementPayload{
		Issuer:             fed.FederationEntity.EntityID,
		Subject:            subordinate.EntityID,
		IssuedAt:           pkg.Unixtime{Time: now},
		ExpiresAt:          pkg.Unixtime{Time: now.Add(time.Duration(subordinateStmtConfig.SubordinateStatementLifetime) * time.Second)},
		SourceEndpoint:     fed.Metadata.FederationEntity.FederationFetchEndpoint,
		JWKS:               subordinate.JWKS,
		Metadata:           subordinate.Metadata,
		MetadataPolicy:     fed.MetadataPolicies,
		Constraints:        subordinateStmtConfig.Constraints,
		CriticalExtensions: subordinateStmtConfig.CriticalExtensions,
		MetadataPolicyCrit: subordinateStmtConfig.MetadataPolicyCrit,
		TrustMarks:         subordinate.TrustMarks,
		Extra:              utils.MergeMaps(true, subordinateStmtConfig.Extra, subordinate.Extra),
	}
}
