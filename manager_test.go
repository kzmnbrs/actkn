package actkn

import (
	"bytes"
	"math/rand"
	"testing"
)

func FuzzManagerEncode(f *testing.F) {
	m := NewManager("biWS2fEqV80PErLR6P-adQFhPhgfCM4zKS8hCpI0Pao")
	f.Add([]byte(`{"id":1,"mode":255}`))

	var dst = make([]byte, 0, 4096)
	f.Fuzz(func(t *testing.T, src []byte) {
		ctx := AcquireCtx()
		defer ReleaseCtx(ctx)

		dst = m.Encode(dst, src, ctx)

		ctx.Reset()
		dec := m.Decode(dst, ctx)

		if !bytes.Equal(src, dec) {
			t.Fatalf("data mismatch: want `%s`, have `%s`", src, dec)
		}
	})
}

func BenchmarkManager_Encode(b *testing.B) {
	m := NewManager("biWS2fEqV80PErLR6P-adQFhPhgfCM4zKS8hCpI0Pao")
	src := make([]byte, 1024)
	rand.Read(src)
	b.ResetTimer()

	b.SetParallelism(16)
	b.RunParallel(func(pb *testing.PB) {
		dst := make([]byte, 0, 2048)
		ctx := AcquireCtx()
		for pb.Next() {
			dst = m.Encode(dst, src, ctx)

			ctx.Reset()
			dst = dst[:0]
		}
		ReleaseCtx(ctx)
	})

	b.ReportAllocs()
}

func BenchmarkManager_DecodeReuse(b *testing.B) {
	m := NewManager("biWS2fEqV80PErLR6P-adQFhPhgfCM4zKS8hCpI0Pao")
	src := make([]byte, 1024)
	rand.Read(src)
	b.ResetTimer()

	b.SetParallelism(16)
	b.RunParallel(func(pb *testing.PB) {
		dst := make([]byte, 0, 2048)
		ctx := AcquireCtx()
		for pb.Next() {
			dst = m.Encode(dst, src, ctx)

			ctx.Reset()
			dst = m.Decode(dst, ctx)
			if !bytes.Equal(dst, src) {
				b.FailNow()
			}

			ctx.Reset()
			dst = dst[:0]
		}
		ReleaseCtx(ctx)
	})

	b.ReportAllocs()
}
