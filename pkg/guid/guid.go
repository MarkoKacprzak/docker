package guid

import (
	"crypto/sha1"
	"fmt"
)

type Guid [16]byte

func NewGuid(source string) *Guid {
	h := sha1.Sum([]byte(source))
	var g Guid
	copy(g[0:], h[0:16])
	return &g
}

func (g *Guid) ToString() string {
	return fmt.Sprintf("%x-%x-%x-%x-%x", g[0:4], g[4:6], g[6:8], g[8:10], g[10:])
}
