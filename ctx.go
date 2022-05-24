package actkn

import (
	"crypto/sha256"
	"hash"
	"sync"
)

type Ctx struct {
	Buf  []byte
	Hash hash.Hash
}

var ctxPool = sync.Pool{}

func NewCtx() *Ctx {
	return &Ctx{
		Buf:  make([]byte, 0, 32),
		Hash: sha256.New(),
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
	c.Buf = c.Buf[:0]
	c.Hash.Reset()
}
