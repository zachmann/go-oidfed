package pkg

import (
	"net/url"
	"time"

	"github.com/lestrrat-go/jwx/jwt"
	"github.com/pkg/errors"

	"github.com/zachmann/go-oidfed/internal"
	"github.com/zachmann/go-oidfed/internal/http"
	"github.com/zachmann/go-oidfed/pkg/unixtime"
)

// EntityConfigurationTrustMarkConfig is a type for specifying the configuration of a TrustMark that should be
// included in an EntityConfiguration
type EntityConfigurationTrustMarkConfig struct {
	TrustMarkID        string                     `yaml:"trust_mark_id"`
	TrustMarkIssuer    string                     `yaml:"trust_mark_issuer"`
	JWT                string                     `yaml:"trust_mark_jwt"`
	Refresh            bool                       `yaml:"refresh"`
	MinLifetime        unixtime.DurationInSeconds `yaml:"min_lifetime"`
	RefreshGracePeriod unixtime.DurationInSeconds `yaml:"refresh_grace_period"`
	expiration         unixtime.Unixtime
	lastTried          unixtime.Unixtime
	sub                string
}

// Verify verifies that the EntityConfigurationTrustMarkConfig is correct and also extracts trust mark id and issuer
// if a trust mark jwt is given as well as sets default values
func (c *EntityConfigurationTrustMarkConfig) Verify(sub string) error {
	c.sub = sub
	if c.MinLifetime.Duration == 0 {
		c.MinLifetime = unixtime.NewDurationInSeconds(10)
	}
	if c.RefreshGracePeriod.Duration == 0 {
		c.RefreshGracePeriod.Duration = time.Hour
	}

	if c.JWT != "" {
		parsed, err := jwt.Parse([]byte(c.JWT))
		if err != nil {
			return err
		}
		c.expiration = unixtime.Unixtime{Time: parsed.Expiration()}
		c.TrustMarkIssuer = parsed.Issuer()
		internal.Logf("Extracted trust mark issuer: %s", c.TrustMarkIssuer)
		tmi, set := parsed.Get("id")
		if !set {
			return errors.New("trustmark id not found in JWT")
		}
		tmiS, ok := tmi.(string)
		if !ok {
			return errors.New("trustmark id in JWT not a string")
		}
		c.TrustMarkID = tmiS
		internal.Logf("Extracted trust mark id: %s\n", c.TrustMarkID)
		return nil
	}
	c.Refresh = true
	if c.TrustMarkID == "" || c.TrustMarkIssuer == "" {
		return errors.New("either trust_mark_jwt or trust_mark_issuer and trust_mark_id must be specified")
	}
	return nil
}

// TrustMarkJWT returns a trust mark jwt for the linked trust mark,
// if needed the trust mark is refreshed using the trust mark issuer's trust mark endpoint
func (c *EntityConfigurationTrustMarkConfig) TrustMarkJWT() (string, error) {
	if !c.Refresh {
		return c.JWT, nil
	}
	if c.JWT != "" && unixtime.Until(c.expiration) > c.MinLifetime.Duration {
		if unixtime.Until(c.expiration) < c.RefreshGracePeriod.Duration {
			go c.refresh()
		}
		return c.JWT, nil
	}
	err := c.refresh()
	return c.JWT, err
}

// refresh refreshes the trust mark at the trust mark issuer's trust mark endpoint
func (c *EntityConfigurationTrustMarkConfig) refresh() error {
	if unixtime.Until(c.lastTried) < time.Minute {
		// Only try once a minute to obtain a new trust mark
		return nil
	}
	tmi, err := GetEntityConfiguration(c.TrustMarkIssuer)
	if err != nil {
		return err
	}
	if tmi.Metadata == nil || tmi.Metadata.FederationEntity == nil || tmi.Metadata.
		FederationEntity.FederationTrustMarkEndpoint == "" {
		return errors.New("could not obtain trust mark endpoint of trust mark issuer")
	}
	endpoint := tmi.Metadata.FederationEntity.FederationTrustMarkEndpoint
	params := url.Values{}
	params.Add("trust_mark_id", c.TrustMarkID)
	params.Add("sub", c.sub)
	res, errRes, err := http.Get(endpoint, params, nil)
	if err != nil {
		c.lastTried = unixtime.Now()
		return err
	}
	if errRes != nil {
		c.lastTried = unixtime.Now()
		return errRes.Err()
	}
	tm, err := ParseTrustMark(res.Body())
	if err != nil {
		return err
	}
	c.JWT = string(tm.jwtMsg.RawJWT)
	if tm.ExpiresAt != nil {
		c.expiration = *tm.ExpiresAt
	} else {
		c.expiration = unixtime.Unixtime{}
	}
	return nil
}
