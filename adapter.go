package cipher

import (
	"math/big"

	"github.com/ThinkiumGroup/go-cipher/math"
)

func PaddedBigBytes(bigint *big.Int, n int) []byte {
	if bigint.BitLen()/8 >= n {
		return bigint.Bytes()
	}
	ret := make([]byte, n)
	math.ReadBits(bigint, ret)
	return ret
}

func SignEncode(r, s *big.Int) []byte {
	sig := make([]byte, 0)
	rb := PaddedBigBytes(r, 32)
	sb := PaddedBigBytes(s, 33)
	sig = append(sig, rb...)
	sig = append(sig, sb...)
	return sig
}

func SignDecode(sign []byte) (r, s *big.Int, err error) {
	r = new(big.Int)
	s = new(big.Int)
	r.SetBytes(sign[:32])
	s.SetBytes(sign[32:])
	return r, s, nil
}
