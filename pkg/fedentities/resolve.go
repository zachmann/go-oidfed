package fedentities

import (
	"time"

	"github.com/gofiber/fiber/v2"

	"github.com/zachmann/go-oidfed/pkg"
	"github.com/zachmann/go-oidfed/pkg/constants"
)

func (fed *FedEntity) AddResolveEndpoint(endpoint EndpointConf) {
	fed.Metadata.FederationEntity.FederationResolveEndpoint = endpoint.URL()
	fed.server.Get(
		endpoint.Path(), func(ctx *fiber.Ctx) error {
			ta := ctx.Query("anchor")
			sub := ctx.Query("sub")
			entityType := ctx.Query("type")
			if ta == "" {
				ctx.Status(fiber.StatusBadRequest)
				return ctx.JSON(pkg.ErrorInvalidRequest("required parameter 'anchor' not given"))
			}
			if sub == "" {
				ctx.Status(fiber.StatusBadRequest)
				return ctx.JSON(pkg.ErrorInvalidRequest("required parameter 'sub' not given"))
			}
			taConfig, err := pkg.GetEntityConfiguration(ta)
			if err != nil {
				ctx.Status(fiber.StatusBadRequest)
				return ctx.JSON(pkg.ErrorInvalidRequest("could not obtain entity configuration for trust anchor"))
			}
			resolver := pkg.TrustResolver{
				TrustAnchors: []pkg.TrustAnchor{
					{
						EntityID: ta,
						JWKS:     taConfig.JWKS,
					},
				},
				StartingEntity: sub,
				Type:           entityType,
			}
			chains := resolver.ResolveToValidChains()
			if len(chains) == 0 {
				ctx.Status(fiber.StatusNotFound)
				return ctx.JSON(pkg.ErrorInvalidRequest("no valid trust path between sub and anchor found"))
			}
			selectedChain := chains[0]
			metadata, _ := selectedChain.Metadata()
			// err cannot be != nil, since ResolveToValidChains only gives chains with valid metadata
			leaf := selectedChain[0]
			var verifiedTMs []pkg.TrustMarkInfo
			for _, tm := range leaf.TrustMarks {
				if err = tm.VerifyFederation(&taConfig.EntityStatementPayload); err == nil {
					verifiedTMs = append(verifiedTMs, tm)
				}
			}
			res := pkg.ResolveResponse{
				Issuer:     fed.FederationEntity.EntityID,
				Subject:    sub,
				IssuedAt:   pkg.Unixtime{Time: time.Now()},
				ExpiresAt:  selectedChain.ExpiresAt(),
				Metadata:   metadata,
				TrustMarks: verifiedTMs,
				TrustChain: selectedChain.Messages(),
			}
			jwt, err := fed.GeneralJWTSigner.ResolveResponseSigner().JWT(res)
			if err != nil {
				ctx.Status(fiber.StatusInternalServerError)
				return ctx.JSON(pkg.ErrorServerError(err.Error()))
			}
			ctx.Set(fiber.HeaderContentType, constants.ContentTypeResolveResponse)
			return ctx.Send(jwt)
		},
	)
}
