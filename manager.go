package actkn

import (
	"bytes"
	"encoding/base64"
	"reflect"
	"unsafe"
)

type Manager struct {
	secret []byte
}

const nEncSig = 44 // base64.URLEncoding.EncodedLen(sha256.Size)

var b64 = base64.URLEncoding

func NewManager(secret string) *Manager {
	return &Manager{secret: []byte(secret)}
}

func (m *Manager) Encode(dst, src []byte, c *Ctx) []byte {
	if len(src) == 0 {
		return dst
	}

	nEncSrc := b64.EncodedLen(len(src))
	nEncMax := nEncSrc + 1 + nEncSig

	if cap(dst) < nEncMax {
		dst = make([]byte, 0, nEncMax)
	}
	dst = dst[:nEncSrc]
	b64.Encode(dst, src)

	dst = unsafeGrow(dst, nEncMax)
	dst[nEncSrc] = '.'

	c.hash.Write(src)
	c.hash.Write(m.secret)
	sig := c.hash.Sum(c.sig[:0])
	b64.Encode(dst[nEncSrc+1:], sig)
	return dst
}

func (m *Manager) DecodeReuse(src []byte, c *Ctx) []byte {
	// b64.EncodedLen(1) + '.' + nEncSig
	if len(src) < 4+1+nEncSig {
		return nil
	}

	dotIdx := bytes.IndexByte(src, '.')
	if dotIdx == -1 {
		return nil
	}

	sig := src[dotIdx+1:]
	if len(sig) != nEncSig {
		return nil
	}
	nDecSig, err := b64.Decode(sig, sig)
	if err != nil {
		return nil
	}
	sig = sig[:nDecSig]

	dat := src[:dotIdx]
	nDecDat, err := b64.Decode(dat, dat)
	if err != nil {
		return nil
	}
	dat = dat[:nDecDat]

	c.hash.Write(dat)
	c.hash.Write(m.secret)
	refSig := c.hash.Sum(c.sig[:0])

	if !bytes.Equal(sig, refSig) {
		return nil
	}

	return dat
}

func unsafeGrow(bs []byte, n int) []byte {
	sh := *(*reflect.SliceHeader)(unsafe.Pointer(&bs))
	return *(*[]byte)(unsafe.Pointer(&reflect.SliceHeader{
		Data: sh.Data,
		Len:  n,
		Cap:  sh.Cap,
	}))
}
