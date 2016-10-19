package evetime

import (
	"strings"
	"time"
)

const (
	ccpformat = "2006-01-02T15:04:05"
)

type EveTime struct {
	time.Time
}

func (c EveTime) String() string {
	return c.Format(ccpformat)
}

func (c *EveTime) UnmarshalJSON(buf []byte) error {
	tt, err := time.Parse(ccpformat, strings.Trim(string(buf), `"`))
	if err != nil {
		return err
	}
	c.Time = tt
	return nil
}
