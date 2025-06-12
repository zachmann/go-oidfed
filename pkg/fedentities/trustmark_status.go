package fedentities

import (
	"slices"

	"github.com/gofiber/fiber/v2"

	"github.com/go-oidfed/lib/pkg"
	"github.com/go-oidfed/lib/pkg/fedentities/storage"
)

// AddTrustMarkStatusEndpoint adds a trust mark status endpoint
func (fed *FedEntity) AddTrustMarkStatusEndpoint(
	endpoint EndpointConf,
	store storage.TrustMarkedEntitiesStorageBackend,
) {
	fed.Metadata.FederationEntity.FederationTrustMarkStatusEndpoint = endpoint.ValidateURL(fed.FederationEntity.EntityID)
	if endpoint.Path == "" {
		return
	}
	fed.server.Get(
		endpoint.Path, func(ctx *fiber.Ctx) error {
			trustMarkID := ctx.Query("trust_mark_id")
			sub := ctx.Query("sub")
			if sub == "" {
				ctx.Status(fiber.StatusBadRequest)
				return ctx.JSON(
					pkg.ErrorInvalidRequest(
						"required parameter 'sub' not given",
					),
				)
			}
			if trustMarkID == "" {
				ctx.Status(fiber.StatusBadRequest)
				return ctx.JSON(
					pkg.ErrorInvalidRequest(
						"required parameter 'trust_mark_id' not given",
					),
				)
			}
			if !slices.Contains(
				fed.TrustMarkIssuer.TrustMarkIDs(),
				trustMarkID,
			) {
				ctx.Status(fiber.StatusNotFound)
				return ctx.JSON(
					pkg.ErrorNotFound("'trust_mark_id' not known"),
				)
			}

			hasTM, err := store.HasTrustMark(trustMarkID, sub)
			if err != nil {
				ctx.Status(fiber.StatusInternalServerError)
				return ctx.JSON(pkg.ErrorServerError(err.Error()))
			}
			return ctx.JSON(
				map[string]any{
					"active": hasTM,
				},
			)
		},
	)
}
