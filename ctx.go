package actkn

import (
	"crypto/sha256"
	"hash"
	"sync"
)

type Ctx struct {
	refSig []byte
	hash   hash.Hash
}

var ctxPool = sync.Pool{}

func NewCtx() *Ctx {
	return &Ctx{
		refSig: make([]byte, 0, 32),
		hash:   sha256.New(),
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
	c.refSig = c.refSig[:0]
	c.hash.Reset()
}
