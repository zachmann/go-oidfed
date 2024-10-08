package fedentities

import (
	"slices"

	"github.com/gofiber/fiber/v2"

	"github.com/zachmann/go-oidfed/pkg"
	"github.com/zachmann/go-oidfed/pkg/constants"
	"github.com/zachmann/go-oidfed/pkg/fedentities/storage"
)

// AddTrustMarkEndpoint adds a trust mark endpoint
func (fed *FedEntity) AddTrustMarkEndpoint(
	endpoint EndpointConf,
	store storage.TrustMarkedEntitiesStorageBackend,
	checkers map[string]EntityChecker,
) {
	fed.Metadata.FederationEntity.FederationTrustMarkEndpoint = endpoint.URL()
	fed.server.Get(
		endpoint.Path(), func(ctx *fiber.Ctx) error {
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
			if !hasTM {
				// subject does not have the trust mark,
				// check if it is entitled to do so
				var checker EntityChecker
				if checkers != nil {
					checker = checkers[trustMarkID]
				}
				if checker == nil {
					ctx.Status(fiber.StatusNotFound)
					return ctx.JSON(
						pkg.ErrorNotFound("subject does not have this trust mark"),
					)
				}
				entityConfig, err := pkg.GetEntityConfiguration(sub)
				if err != nil {
					ctx.Status(fiber.StatusBadRequest)
					return ctx.JSON(pkg.ErrorInvalidRequest("could not obtain entity configuration"))
				}
				ok, _, errResponse := checker.Check(
					entityConfig, entityConfig.Metadata.GuessEntityTypes(),
				)
				if !ok {
					ctx.Status(fiber.StatusNotFound)
					return ctx.JSON(
						pkg.ErrorNotFound(
							"subject does not have this trust mark and is not" +
								" entitled to get it: " + errResponse.ErrorDescription,
						),
					)
				}
				// ok, so we add sub to the list and issue the trust mark
				if err = store.Write(trustMarkID, sub); err != nil {
					ctx.Status(fiber.StatusInternalServerError)
					return ctx.JSON(pkg.ErrorServerError(err.Error()))
				}
			}
			tm, err := fed.IssueTrustMark(trustMarkID, sub)
			if err != nil {
				if err != nil {
					ctx.Status(fiber.StatusInternalServerError)
					return ctx.JSON(pkg.ErrorServerError(err.Error()))
				}
			}
			ctx.Set(fiber.HeaderContentType, constants.ContentTypeTrustMark)
			return ctx.SendString(tm.TrustMarkJWT)
		},
	)
}
