package pkg

import (
	"github.com/lestrrat-go/jwx/jwt"
)

// TrustMark is a type for holding a trust mark
type TrustMark struct {
	ID           string    `json:"id"`
	TrustMarkJWT jwt.Token `json:"trust_mark"`
}
