package cipher

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"hash"
	"math/big"

	"github.com/ThinkiumGroup/go-cipher/math"
	"github.com/ThinkiumGroup/go-cipher/vrf/secp256k1VRF"
)

type (
	Hash [HashLength]byte
)

const (
	HashLength    = 32
	SECP256K1SHA3 = "secp256k1_sha3"
)

var (
	RealCipher    = NewCipher(SECP256K1SHA3)
	SystemPrivKey ECCPrivateKey

	ErrInvalidCurve               = errors.New("invalid elliptic curve")
	ErrSharedKeyIsPointAtInfinity = errors.New("shared key is point at infinity")
	ErrSharedKeyTooBig            = errors.New("shared key params are too big")

	secp256k1N, _  = new(big.Int).SetString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)
	secp256k1halfN = new(big.Int).Div(secp256k1N, big.NewInt(2))
)

func NewCipher(name string) Cipher {
	switch name {
	case SECP256K1SHA3:
		return NewSecpCipher()
	}
	return nil
}

type Cipher interface {
	Name() string
	GenerateKey() (priv ECCPrivateKey, err error)
	Sign(priv []byte, hash []byte) (sig []byte, err error)
	Verify(pub []byte, hash []byte, sig []byte) bool
	RecoverPub(hash, sig []byte) ([]byte, error)

	PrivToBytes(priv ECCPrivateKey) []byte
	PubToBytes(pub ECCPublicKey) []byte
	BytesToPriv(d []byte) (ECCPrivateKey, error)
	BytesToPub(pub []byte) (ECCPublicKey, error)
	PubFromNodeId(id []byte) []byte
	PubToNodeIdBytes(pub []byte) ([]byte, error)

	PubFromPriv(priv []byte) ([]byte, error)

	Hasher() hash.Hash

	LengthOfPublicKey() int  // number of bytes of public key
	LengthOfPrivateKey() int // number of bytes of private key
	LengthOfSignature() int  // number of bytes of signature
	LengthOfHash() int       // number of bytes of input Hash

	ValidateSignatureValues(v byte, r, s *big.Int, homestead bool) bool
}

type ECCPrivateKey interface {
	elliptic.Curve
	crypto.Signer
	GetPublicKey() ECCPublicKey
	ToECDSA() *ecdsa.PrivateKey
	FromECDSA(key *ecdsa.PrivateKey) ECCPrivateKey
	ToBytes() []byte
	FromBytes(priv []byte) (ECCPrivateKey, error)
	VrfEval(m []byte) (index [32]byte, proof []byte)
	GenerateShared(k ECCPublicKey, skLen, macLen int) (sk []byte, err error)
}

type ECCPublicKey interface {
	elliptic.Curve
	ToECDSA() *ecdsa.PublicKey
	FromECDSA(key *ecdsa.PublicKey) ECCPublicKey
	ToBytes() []byte
	FromBytes(pub []byte) (ECCPublicKey, error)
	ToNodeIDBytes() []byte
	FromBytesNodeID(id []byte) ECCPublicKey
	ToAddress() []byte
	VrfProofToHash(m, proof []byte) (index [32]byte, err error)
	VrfVerify(m, proof []byte, index [32]byte) bool
}

func VrfEval(priv ECCPrivateKey, m []byte) (index [32]byte, proof []byte) {
	vrfkey := secp256k1VRF.PrivateKey{PrivateKey: priv.ToECDSA()}
	return vrfkey.Evaluate(m)
}

func VrfVerify(pub ECCPublicKey, seed, proof []byte, index [32]byte) bool {
	proofIndex, err := VrfProofToHash(pub, seed, proof)
	if err != nil {
		return false
	}
	return bytes.Equal(index[:], proofIndex[:])
}

func VrfProofToHash(pub ECCPublicKey, m, proof []byte) (index [32]byte, err error) {
	vrfkey := secp256k1VRF.PublicKey{PublicKey: pub.ToECDSA()}
	return vrfkey.ProofToHash(m, proof)
}

func ValidateSecpSigValues(v byte, r, s *big.Int) bool {
	if r.Cmp(math.Big1) < 0 || s.Cmp(math.Big1) < 0 {
		return false
	}
	return r.Cmp(secp256k1N) < 0 && s.Cmp(secp256k1N) < 0 && (v == 0 || v == 1)
}

func MaxSharedKeyLength(p ECCPublicKey) int {
	pub := p.ToECDSA()
	return (pub.Curve.Params().BitSize + 7) / 8
}

// ValidateSignatureValues verifies whether the signature values are valid with
// the given chain rules. The v value is assumed to be either 0 or 1.
func ValidateSignatureValues(v byte, r, s *big.Int, homestead bool) bool {
	if r.Cmp(math.Big1) < 0 || s.Cmp(math.Big1) < 0 {
		return false
	}
	// reject upper range of s values (ECDSA malleability)
	// see discussion in secp256k1/libsecp256k1/include/secp256k1.h
	if homestead && s.Cmp(secp256k1halfN) > 0 {
		return false
	}
	// Frontier: allow s to be in full N range
	return r.Cmp(secp256k1N) < 0 && s.Cmp(secp256k1N) < 0 && (v == 0 || v == 1)
}
