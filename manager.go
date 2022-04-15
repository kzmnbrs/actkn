package actkn

import (
	"bytes"
	"encoding/ascii85"
	"reflect"
	"unsafe"
)

type Manager struct {
	secret []byte
}

func NewManager(secret string) *Manager {
	return &Manager{secret: []byte(secret)}
}

// Encode encodes ascii85(dat) + '~' + ascii85(sha256(dat + secret)) in the dst slice.
//
// It's safe to release Ctx after this function returns.
func (m *Manager) Encode(dst, dat []byte, c *Ctx) []byte {
	const nMaxSepPlusSig = 45 // ascii85.MaxEncodedLen(len("~") + sha256.Sum256(...))

	// Calculating how many bytes at max is required to fit the entire token.
	nMax := ascii85.MaxEncodedLen(len(dat))
	if cap(dst) < nMax+nMaxSepPlusSig {
		dst = make([]byte, nMax, nMax+nMaxSepPlusSig)
	}

	// Encoding each token part. Size calibration on each step is required
	// since ascii85 encodes zeros with a single byte.
	dst = unsafeSetLen(dst, nMax)
	nDat := ascii85.Encode(dst, dat)
	dst = unsafeSetLen(dst, nDat)

	dst = append(dst, '~')
	dst = unsafeSetLen(dst, nDat+nMaxSepPlusSig)

	c.hash.Write(dat)
	c.hash.Write(m.secret)

	c.refSig = c.hash.Sum(c.refSig)
	nSig := ascii85.Encode(dst[nDat+1:], c.refSig)
	return unsafeSetLen(dst, nDat+1+nSig)
}

// DecodeReuse verifies the given token against the singing secret
// and decodes its contents to the tok.Data array.
//
// It's safe to release Ctx after this function returns.
func (m *Manager) DecodeReuse(tok []byte, c *Ctx) ([]byte, bool) {
	const nMaxSig = 40 // ascii85.MaxEncodedLen(sha256.Sum256(...))

	sep := bytes.IndexByte(tok, '~')
	if sep == -1 || sep == len(tok)-1 {
		return nil, false
	}

	a85dat := tok[:sep]
	a85sig := tok[sep+1:]

	if len(a85sig) > nMaxSig {
		return nil, false
	}

	var (
		dat, sig []byte
		ok       bool
	)
	if dat, ok = decodeA85(tok[:sep], a85dat); !ok {
		return nil, false
	}
	if sig, ok = decodeA85(tok[sep+1:], a85sig); !ok {
		return nil, false
	}

	c.hash.Write(dat)
	c.hash.Write(m.secret)
	c.refSig = c.hash.Sum(c.refSig)
	return dat, bytes.Equal(sig, c.refSig)
}

func decodeA85(dst, dat []byte) ([]byte, bool) {
	n, _, err := ascii85.Decode(dst, dat, true)
	return dst[:n], err == nil
}

func unsafeSetLen(b []byte, newLen int) []byte {
	sh := *(*reflect.SliceHeader)(unsafe.Pointer(&b))
	sh.Len = newLen
	return *(*[]byte)(unsafe.Pointer(&sh))
}
