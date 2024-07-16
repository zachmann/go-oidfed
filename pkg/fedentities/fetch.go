package fedentities

import (
	"github.com/gofiber/fiber/v2"

	"github.com/zachmann/go-oidfed/pkg"
	"github.com/zachmann/go-oidfed/pkg/constants"
	"github.com/zachmann/go-oidfed/pkg/fedentities/storage"
)

func (fed *FedEntity) AddFetchEndpoint(endpoint EndpointConf, store storage.SubordinateStorageBackend) {
	fed.Metadata.FederationEntity.FederationFetchEndpoint = endpoint.URL()
	fed.server.Get(
		endpoint.Path(), func(ctx *fiber.Ctx) error {
			iss := ctx.Query("iss")
			sub := ctx.Query("sub")
			if iss == "" {
				ctx.Status(fiber.StatusBadRequest)
				return ctx.JSON(pkg.ErrorInvalidRequest("required parameter 'iss' not given"))
			}
			if iss != fed.FederationEntity.EntityID {
				ctx.Status(fiber.StatusNotFound)
				return ctx.JSON(
					pkg.ErrorInvalidIssuer(
						"cannot fetch entity statements for this issuer from this endpoint",
					),
				)
			}
			if sub == "" {
				jwt, err := fed.EntityConfigurationJWT()
				if err != nil {
					ctx.Status(fiber.StatusInternalServerError)
					return ctx.JSON(pkg.ErrorServerError(err.Error()))
				}
				ctx.Set(fiber.HeaderContentType, constants.ContentTypeEntityStatement)
				return ctx.Send(jwt)
			}
			info, err := store.Q().Subordinate(sub)
			if err != nil {
				ctx.Status(fiber.StatusInternalServerError)
				return ctx.JSON(pkg.ErrorServerError(err.Error()))
			}
			if info == nil {
				ctx.Status(fiber.StatusNotFound)
				return ctx.JSON(pkg.ErrorNotFound("the requested entity identifier is not found"))
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
