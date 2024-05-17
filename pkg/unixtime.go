package pkg

import (
	"encoding/json"
	"math"
	"time"

	"github.com/pkg/errors"
)

// Unixtime is a type for handling unix timestamps
type Unixtime struct {
	time.Time
}

// UnmarshalJSON implements the json.Unmarshaler interface.
func (u *Unixtime) UnmarshalJSON(src []byte) error {
	var f float64
	if err := json.Unmarshal(src, &f); err != nil {
		return err
	}
	sec, dec := math.Modf(f)
	u.Time = time.Unix(int64(sec), int64(dec*(1e9)))
	return nil
}

// MarshalJSON implements the json.Marshaler interface.
func (u Unixtime) MarshalJSON() ([]byte, error) {
	return json.Marshal(float64(u.UnixNano()) / 1e9)
}

func verifyTime(iat, exp Unixtime) error {
	now := time.Now()
	if !iat.IsZero() && iat.After(now) {
		return errors.New("not yet valid")
	}
	if !exp.IsZero() && exp.Before(now) {
		return errors.New("expired")
	}
	return nil
}
