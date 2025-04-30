package fedentities

import (
	"github.com/gofiber/fiber/v2"

	"github.com/zachmann/go-oidfed/internal/utils"
	"github.com/zachmann/go-oidfed/pkg"
	"github.com/zachmann/go-oidfed/pkg/constants"
	"github.com/zachmann/go-oidfed/pkg/fedentities/storage"
)

// AddFetchEndpoint adds a fetch endpoint
func (fed *FedEntity) AddFetchEndpoint(endpoint EndpointConf, store storage.SubordinateStorageBackend) {
	fed.Metadata.FederationEntity.FederationFetchEndpoint = endpoint.ValidateURL(fed.FederationEntity.EntityID)
	if endpoint.Path == "" {
		return
	}
	fed.server.Get(
		endpoint.Path, func(ctx *fiber.Ctx) error {
			sub := ctx.Query("sub")
			if sub == "" {
				ctx.Status(fiber.StatusBadRequest)
				return ctx.JSON(pkg.ErrorInvalidRequest("required parameter 'sub' not given"))
			}
			info, err := store.Subordinate(sub)
			if err != nil {
				ctx.Status(fiber.StatusInternalServerError)
				return ctx.JSON(pkg.ErrorServerError(err.Error()))
			}
			if info == nil {
				info, err = store.Subordinate(utils.TheOtherEntityIDComparisonOption(sub))
				if info == nil {
					ctx.Status(fiber.StatusNotFound)
					return ctx.JSON(pkg.ErrorNotFound("the requested entity identifier is not found"))
				}
			}
			payload := fed.CreateSubordinateStatement(info)
			jwt, err := fed.SignEntityStatement(payload)
			if err != nil {
				ctx.Status(fiber.StatusInternalServerError)
				return ctx.JSON(pkg.ErrorServerError(err.Error()))
			}
			ctx.Set(fiber.HeaderContentType, constants.ContentTypeEntityStatement)
			return ctx.Send(jwt)
		},
	)
}
