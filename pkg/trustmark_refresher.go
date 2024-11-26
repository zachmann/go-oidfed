package pkg

import (
	"time"

	"github.com/lestrrat-go/jwx/jwt"
	"github.com/pkg/errors"

	"github.com/zachmann/go-oidfed/pkg/unixtime"
)

type EntityConfigurationTrustMarkConfig struct {
	TrustMarkID        string                     `yaml:"trust_mark_id"`
	TrustMarkIssuer    string                     `yaml:"trust_mark_issuer"`
	JWT                string                     `yaml:"trust_mark_jwt"`
	Refresh            bool                       `yaml:"refresh"`
	MinLifetime        unixtime.DurationInSeconds `yaml:"min_lifetime"`
	RefreshGracePeriod unixtime.DurationInSeconds `yaml:"refresh_grace_period"`
	expiration         unixtime.Unixtime
}

func (c *EntityConfigurationTrustMarkConfig) Verify() error {
	if c.MinLifetime.Duration == 0 {
		c.MinLifetime = unixtime.NewDurationInSeconds(10)
	}
	if c.RefreshGracePeriod.Duration == 0 {
		c.RefreshGracePeriod.Duration = time.Hour
	}

	if c.JWT != "" {
		parsed, err := jwt.Parse([]byte(c.JWT), nil)
		if err != nil {
			return err
		}
		c.expiration = unixtime.Unixtime{Time: parsed.Expiration()}
		c.TrustMarkIssuer = parsed.Issuer()
		tmi, set := parsed.Get("trust_mark_id")
		if !set {
			return errors.New("trust_mark_id not found in JWT")
		}
		tmiS, ok := tmi.(string)
		if !ok {
			return errors.New("trust_mark_id in JWT not a string")
		}
		c.TrustMarkID = tmiS
		return nil
	}
	c.Refresh = true
	if c.TrustMarkID == "" || c.TrustMarkIssuer == "" {
		return errors.New("either trust_mark_jwt or trust_mark_issuer and trust_mark_id must be specified")
	}
	return nil
}

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

func (c *EntityConfigurationTrustMarkConfig) refresh() error {
	//TODO
	return nil
}
