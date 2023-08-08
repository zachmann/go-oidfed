package server

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/log"

	"github.com/zachmann/go-oidcfed/examples/ta/config"
	"github.com/zachmann/go-oidcfed/examples/ta/oidcfed"
	"github.com/zachmann/go-oidcfed/examples/ta/server/routes"
)

var server *fiber.App

var serverConfig = fiber.Config{
	ReadTimeout:    30 * time.Second,
	WriteTimeout:   90 * time.Second,
	IdleTimeout:    150 * time.Second,
	ReadBufferSize: 8192,
}

// Init initializes the server
func Init() {
	server = fiber.New(serverConfig)
	addMiddlewares(server)
	addRoutes(server)
}

type jwtAble interface {
	JWT() ([]byte, error)
}

func sendJWTAble(ctx *fiber.Ctx, j jwtAble) error {
	if ctx.Query("json") != "" {
		return ctx.JSON(j)
	}
	data, err := j.JWT()
	if err != nil {
		return err
	}
	ctx.Set("Content-Type", "application/entity-statement+jwt")
	return ctx.Send(data)
}

func addRoutes(s fiber.Router) {
	s.Get(
		routes.FederationConfigurationPath, func(ctx *fiber.Ctx) error {
			return sendJWTAble(ctx, oidcfed.GetEntityConfiguration())
		},
	)
	s.Post(
		routes.EnrollEndpointPath, func(ctx *fiber.Ctx) error {
			req := struct {
				Subject    string `json:"sub" xml:"sub" form:"sub"`
				EntityType string `json:"entity_type" xml:"entity_type" form:"entity_type"`
			}{}
			if err := ctx.BodyParser(&req); err != nil {
				return err
			}
			status, err := oidcfed.EnrollEntity(req.Subject, req.EntityType)
			ctx.Status(status)
			if err != nil {
				return ctx.SendString(err.Error())
			}
			return nil
		},
	)
	s.Get(
		routes.ListEndpointPath, func(ctx *fiber.Ctx) error {
			entityType := ctx.Query("entity_type")
			list, err := oidcfed.ListSubordinates(entityType)
			if err != nil {
				return err
			}
			return ctx.JSON(list)
		},
	)
	s.Get(
		routes.FetchEndpointPath, func(ctx *fiber.Ctx) error {
			iss := ctx.Query("iss")
			if iss != "" && iss != config.Get().EntityID {
				ctx.Status(http.StatusBadRequest)
				return ctx.SendString(fmt.Sprintf("you can only fetch statements issued by %s", config.Get().EntityID))
			}
			sub := ctx.Query("sub")
			if sub == "" {
				return sendJWTAble(ctx, oidcfed.GetEntityConfiguration())
			}
			data, status, err := oidcfed.FetchEntityStatement(sub)
			if err != nil {
				if status != 0 {
					ctx.Status(status)
				}
				return err
			}
			ctx.Status(status)
			return ctx.Send(data)
		},
	)
}

func start(s *fiber.App) {
	log.Fatal(s.Listen(fmt.Sprintf(":%d", config.Get().ServerPort)))
}

// Start starts the server
func Start() {
	start(server)
}
