package fedentities

import (
	"slices"

	arrays "github.com/adam-hanna/arrayOperations"
	"github.com/gofiber/fiber/v2"

	"github.com/go-oidfed/lib/pkg"
	"github.com/go-oidfed/lib/pkg/fedentities/storage"
)

// AddSubordinateListingEndpoint adds a subordinate listing endpoint
func (fed *FedEntity) AddSubordinateListingEndpoint(
	endpoint EndpointConf, store storage.SubordinateStorageBackend,
	trustMarkStore storage.TrustMarkedEntitiesStorageBackend,
) {
	fed.Metadata.FederationEntity.FederationListEndpoint = endpoint.ValidateURL(fed.FederationEntity.EntityID)
	if endpoint.Path == "" {
		return
	}
	fed.server.Get(
		endpoint.Path, func(ctx *fiber.Ctx) error {
			return handleSubordinateListing(
				ctx, ctx.Query("entity_type"), ctx.QueryBool("trust_marked"),
				ctx.Query("trust_mark_id"),
				ctx.QueryBool("intermediate"),
				store.Active(),
				trustMarkStore,
			)
		},
	)
}

func filterEntityType(info storage.SubordinateInfo, value any) bool {
	v, ok := value.(string)
	return ok && slices.Contains(info.EntityTypes, v)
}

func handleSubordinateListing(
	ctx *fiber.Ctx, entityType string, trustMarked bool, trustMarkID string,
	intermediate bool, q storage.SubordinateStorageQuery, trustMarkedEntitiesStorage storage.
		TrustMarkedEntitiesStorageBackend,
) error {
	if intermediate {
		ctx.Status(fiber.StatusBadRequest)
		return ctx.JSON(pkg.ErrorUnsupportedParameter("parameter 'intermediate' is not supported"))
	}
	if trustMarkedEntitiesStorage == nil {
		if trustMarked {
			ctx.Status(fiber.StatusBadRequest)
			return ctx.JSON(pkg.ErrorUnsupportedParameter("parameter 'trust_marked' is not supported"))
		}
		if trustMarkID != "" {
			ctx.Status(fiber.StatusBadRequest)
			return ctx.JSON(pkg.ErrorUnsupportedParameter("parameter 'trust_mark_id' is not supported"))
		}
	}

	if q == nil {
		return ctx.JSON([]string{})
	}
	if entityType != "" {
		if err := q.AddFilter(filterEntityType, entityType); err != nil {
			ctx.Status(fiber.StatusInternalServerError)
			return ctx.JSON(pkg.ErrorServerError(err.Error()))
		}
	}

	ids, err := q.EntityIDs()
	if err != nil {
		ctx.Status(fiber.StatusInternalServerError)
		return ctx.JSON(pkg.ErrorServerError(err.Error()))
	}

	if trustMarkID != "" || trustMarked {
		trustMarkedEntities, err := trustMarkedEntitiesStorage.Active(trustMarkID)
		if err != nil {
			ctx.Status(fiber.StatusInternalServerError)
			return ctx.JSON(pkg.ErrorServerError(err.Error()))
		}
		ids = arrays.Intersect(ids, trustMarkedEntities)
	}

	return ctx.JSON(ids)
}
