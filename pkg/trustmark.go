package pkg

import (
	"github.com/lestrrat-go/jwx/jwt"
)

type TrustMark struct {
	ID           string    `json:"id"`
	TrustMarkJWT jwt.Token `json:"trust_mark"`
}
