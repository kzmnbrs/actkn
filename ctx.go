package actkn

import (
	"crypto/sha256"
	"hash"
	"sync"
)

type Ctx struct {
	sig  [32]byte
	hash hash.Hash
}

var ctxPool = sync.Pool{}

func NewCtx() *Ctx {
	return &Ctx{
		sig:  [32]byte{},
		hash: sha256.New(),
	}
}

func AcquireCtx() *Ctx {
	v := ctxPool.Get()
	if c, ok := v.(*Ctx); ok {
		return c
	}
	return NewCtx()
}

func ReleaseCtx(c *Ctx) {
	c.Reset()
	ctxPool.Put(c)
}

func (c *Ctx) Reset() {
	c.hash.Reset()
}
