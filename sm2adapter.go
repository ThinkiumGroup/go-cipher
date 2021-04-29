package cipher

import (
	"crypto/rand"
	"fmt"

	"github.com/tjfoc/gmsm/sm2"
)

func Sm2Sign(hash []byte, prv *sm2.PrivateKey) (sig []byte, err error) {
	if len(hash) != 32 {
		return nil, fmt.Errorf("hash is required to be exactly 32 bytes (%d)", len(hash))
	}
	r, s, err := sm2.Sm2Sign(prv, hash, nil, rand.Reader)
	if err != nil {
		return nil, err
	}
	return SignEncode(r, s), nil
}

func SM2VerifySignature(pubkey *sm2.PublicKey, hash, signature []byte) bool {
	r, s, err := SignDecode(signature)
	if err != nil {
		return false
	}
	// return sm2.Verify(pubkey, hash, r, s)
	return sm2.Sm2Verify(pubkey, hash, nil, r, s)
}
