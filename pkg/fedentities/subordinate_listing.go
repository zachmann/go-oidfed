package fedentities

import (
	"github.com/gofiber/fiber/v2"

	"github.com/zachmann/go-oidfed/pkg"
	"github.com/zachmann/go-oidfed/pkg/fedentities/storage"
)

func (fed *FedEntity) AddSubordinateListingEndpoint(endpoint EndpointConf, store storage.SubordinateStorageBackend) {
	fed.Metadata.FederationEntity.FederationListEndpoint = endpoint.URL()
	fed.server.Get(
		endpoint.Path(), func(ctx *fiber.Ctx) error {
			return handleSubordinateListing(
				ctx, ctx.Query("entity_type"), ctx.QueryBool("trust_marked"),
				ctx.Query("trust_mark_id"),
				ctx.QueryBool("intermediate"),
				store.Q(),
			)
		},
	)
}

func filterEntityType(info storage.SubordinateInfo, value any) bool {
	v, ok := value.(string)
	return ok && info.EntityType == v
}

func handleSubordinateListing(
	ctx *fiber.Ctx, entityType string, trustMarked bool, trustMarkID string,
	intermediate bool, q storage.SubordinateStorageQuery,
) error {
	if q == nil {
		return ctx.JSON([]string{})
	}
	if entityType != "" {
		if err := q.AddFilter(filterEntityType, entityType); err != nil {
			ctx.Status(fiber.StatusInternalServerError)
			return ctx.JSON(pkg.ErrorServerError(err.Error()))
		}
	}
	// TODO add other filters
	if intermediate {
		ctx.Status(fiber.StatusBadRequest)
		return ctx.JSON(pkg.ErrorUnsupportedParameter("parameter 'intermediate' is not supported"))
	}
	ids, err := q.EntityIDs()
	if err != nil {
		ctx.Status(fiber.StatusInternalServerError)
		return ctx.JSON(pkg.ErrorServerError(err.Error()))
	}
	return ctx.JSON(ids)
}
