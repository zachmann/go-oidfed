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
	fed.Metadata.FederationEntity.FederationTrustMarkEndpoint = endpoint.ValidateURL(fed.FederationEntity.EntityID)
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
				return issueAndSendTrustMark(ctx, fed, trustMarkID, sub)
			case storage.StatusBlocked:
				ctx.Status(fiber.StatusForbidden)
				return ctx.JSON(pkg.ErrorInvalidRequest("subject cannot obtain this trust mark"))
			case storage.StatusPending:
				ctx.Status(fiber.StatusAccepted)
				return ctx.JSON(pkg.ErrorInvalidRequest("approval pending"))
			case storage.StatusInactive:
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
				if err = store.Approve(trustMarkID, sub); err != nil {
					ctx.Status(fiber.StatusInternalServerError)
					return ctx.JSON(pkg.ErrorServerError(err.Error()))
				}
			}
			return issueAndSendTrustMark(ctx, fed, trustMarkID, sub)
		},
	)
}

func issueAndSendTrustMark(
	ctx *fiber.Ctx, fedEntity *FedEntity, trustMarkID, sub string,
) error {
	tm, err := fedEntity.IssueTrustMark(trustMarkID, sub)
	if err != nil {
		if err != nil {
			ctx.Status(fiber.StatusInternalServerError)
			return ctx.JSON(pkg.ErrorServerError(err.Error()))
		}
	}
	ctx.Set(fiber.HeaderContentType, constants.ContentTypeTrustMark)
	return ctx.SendString(tm.TrustMarkJWT)
}
