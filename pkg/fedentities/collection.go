package fedentities

import (
	"github.com/gofiber/fiber/v2"

	"github.com/zachmann/go-oidfed/pkg"
	"github.com/zachmann/go-oidfed/pkg/apimodel"
)

// TODO allow limiting the collection endpoint to certain trust anchors

const defaultPagingLimit = 100

// AddEntityCollectionEndpoint adds an entity collection endpoint
func (fed *FedEntity) AddEntityCollectionEndpoint(endpoint EndpointConf) {
	if fed.Metadata.FederationEntity.Extra == nil {
		fed.Metadata.FederationEntity.Extra = make(map[string]interface{})
	}
	fed.Metadata.FederationEntity.Extra["federation_collection_endpoint"] = endpoint.ValidateURL(fed.FederationEntity.EntityID)
	if endpoint.Path == "" {
		return
	}
	fed.server.Get(
		endpoint.Path, func(ctx *fiber.Ctx) error {
			var req apimodel.EntityCollectionRequest
			if err := ctx.QueryParser(&req); err != nil {
				ctx.Status(fiber.StatusBadRequest)
				return ctx.JSON(pkg.ErrorInvalidRequest("could not parse request parameters: " + err.Error()))
			}
			if req.FromEntityID != "" {
				ctx.Status(fiber.StatusBadRequest)
				return ctx.JSON(pkg.ErrorUnsupportedParameter("parameter 'from_entity_id' is not yet supported"))
			}
			if req.TrustAnchor == "" {
				req.TrustAnchor = fed.FederationEntity.EntityID
			}
			if req.Limit != 0 {
				ctx.Status(fiber.StatusBadRequest)
				return ctx.JSON(pkg.ErrorUnsupportedParameter("parameter 'limit' is not yet supported"))
			}
			collector := pkg.SimpleEntityCollector{}
			entities := collector.CollectEntities(req)

			res := pkg.EntityCollectionResponse{
				FederationEntities: entities,
			}
			return ctx.JSON(res)
		},
	)
}
