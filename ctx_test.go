package actkn

import "sync"

type testCtx struct {
	c   *Ctx
	dst []byte
}

var testCtxPool = sync.Pool{}

func newTestCtx() *testCtx {
	return &testCtx{
		c:   NewCtx(),
		dst: make([]byte, 0, 512),
	}
}

func acquireTestCtx() *testCtx {
	v := testCtxPool.Get()
	if tcx, ok := v.(*testCtx); ok {
		return tcx
	}
	return newTestCtx()
}

func releaseTestCtx(tcx *testCtx) {
	tcx.Reset()
	testCtxPool.Put(tcx)
}

func (tcx *testCtx) Reset() {
	tcx.c.Reset()
	tcx.dst = tcx.dst[:0]
}
