package actkn

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

type td struct {
	dat []byte
	tok []byte
}

var m = NewManager("O7DQ7yHnqaIJ4oNdS98ZDvCTah2tfb6CBO8_vID-VxY")

func tdOK() td {
	return td{
		dat: []byte("{\"name\":\"Borisick\",\"mode\":255}"),
		tok: []byte("HQm?9D.OnP,!p3gBlduuCEb;RD/Wrr,!%J:215~@:h:BT:N)DN)X8dP602@C>b=j:);EKh[md(=LsVd"),
	}
}

func TestManager_DecodeReuse(t *testing.T) {
	type tc struct {
		name  string
		td    td
		valid bool
	}
	tcs := []tc{
		{"ok", tdOK(), true},
		{"sep", td{
			dat: nil,
			tok: []byte("~"),
		}, false},
		{"nil", td{dat: nil, tok: nil}, false},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			tcx := acquireTestCtx()
			defer releaseTestCtx(tcx)

			tokCpy := make([]byte, len(tc.td.tok))
			copy(tokCpy, tc.td.tok)

			dat, valid := m.DecodeReuse(tokCpy, tcx.c)
			assert.Equal(t, tc.valid, valid)
			if !valid {
				return
			}

			assert.Equal(t, tc.td.dat, dat)
			assert.NotEqual(t, tc.td.tok, tokCpy)
		})
	}
}

func BenchmarkManager_Encode(b *testing.B) {
	td := tdOK()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		var tok []byte
		for pb.Next() {
			tcx := acquireTestCtx()
			tok = m.Encode(tcx.dst, td.dat, tcx.c)
			if !bytes.Equal(tok, td.tok) {
				b.FailNow()
			}
			releaseTestCtx(tcx)
		}
		_ = tok
	})
	b.ReportAllocs()
}

func BenchmarkManager_DecodeReuse(b *testing.B) {
	td := tdOK()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		var (
			dat []byte
			ok  bool
		)
		for pb.Next() {
			tcx := acquireTestCtx()
			tcx.dst = append(tcx.dst, td.tok...)
			dat, ok = m.DecodeReuse(tcx.dst, tcx.c)
			if !bytes.Equal(dat, td.dat) || !ok {
				b.FailNow()
			}
			releaseTestCtx(tcx)
		}
		_ = dat
		_ = ok
	})
	b.ReportAllocs()
}
