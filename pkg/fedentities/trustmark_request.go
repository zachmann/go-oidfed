package fedentities

import (
	"slices"

	"github.com/gofiber/fiber/v2"

	"github.com/go-oidfed/lib/pkg"
	"github.com/go-oidfed/lib/pkg/fedentities/storage"
)

// AddTrustMarkRequestEndpoint adds an endpoint where entities can request to
// be entitled for a trust mark
func (fed *FedEntity) AddTrustMarkRequestEndpoint(
	endpoint EndpointConf,
	store storage.TrustMarkedEntitiesStorageBackend,
) {
	if fed.Metadata.FederationEntity.Extra == nil {
		fed.Metadata.FederationEntity.Extra = make(map[string]interface{})
	}
	fed.Metadata.FederationEntity.Extra["trust_mark_request"] = endpoint.ValidateURL(fed.FederationEntity.EntityID)
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

			status, err := store.TrustMarkedStatus(trustMarkID, sub)
			if err != nil {
				ctx.Status(fiber.StatusInternalServerError)
				return ctx.JSON(pkg.ErrorServerError(err.Error()))
			}
			switch status {
			case storage.StatusActive:
				ctx.Status(fiber.StatusNoContent)
				return nil
			case storage.StatusBlocked:
				ctx.Status(fiber.StatusForbidden)
				return ctx.JSON(pkg.ErrorInvalidRequest("subject cannot obtain this trust mark"))
			case storage.StatusPending:
				ctx.Status(fiber.StatusAccepted)
				return nil
			case storage.StatusInactive:
				fallthrough
			default:
				if err = store.Request(trustMarkID, sub); err != nil {
					ctx.Status(fiber.StatusInternalServerError)
					return ctx.JSON(pkg.ErrorServerError(err.Error()))
				}
				ctx.Status(fiber.StatusAccepted)
				return nil
			}
		},
	)
}
