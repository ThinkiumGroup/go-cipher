package cipher

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"fmt"
	"hash"
	"io"
	"math/big"

	"github.com/ThinkiumGroup/go-cipher/math"
	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/sm3"
)

const (
	gmPubSize  = 65
	gmPrivSize = 32
	gmSigSize  = 65
)

func NewGMCipher() Cipher {
	signer := new(GMSigner)
	return signer
}

type GMSigner struct{}

func (s GMSigner) Name() string {
	return GMSM
}

func (s GMSigner) GenerateKey() (priv ECCPrivateKey, err error) {
	sm2priv, err := sm2.GenerateKey()
	if err != nil {
		return nil, err
	}
	return (*GMPrivateKey)(sm2priv), nil
}

func (s GMSigner) Sign(prib []byte, hash []byte) ([]byte, error) {
	eccpriv, err := new(GMPrivateKey).FromBytes(prib)
	if err != nil {
		return nil, err
	}
	priv, ok := eccpriv.(*GMPrivateKey)
	if priv == nil || !ok {
		return nil, errors.New("invalid sm private key")
	}
	return Sm2Sign(hash, (*sm2.PrivateKey)(priv))
}

func (s GMSigner) Verify(pub []byte, hash []byte, sig []byte) bool {
	pubk, err := new(GMPublicKey).FromBytes(pub)
	if err != nil {
		return false
	}
	pubkey, ok := pubk.(*GMPublicKey)
	if pubkey == nil || !ok {
		return false
	}
	return SM2VerifySignature((*sm2.PublicKey)(pubkey), hash, sig)
}

func (s GMSigner) PrivToBytes(priv ECCPrivateKey) []byte {
	return priv.ToBytes()
}

func (s GMSigner) PubToBytes(pub ECCPublicKey) []byte {
	return pub.ToBytes()
}

func (s GMSigner) BytesToPriv(d []byte) (ECCPrivateKey, error) {
	return new(GMPrivateKey).FromBytes(d)
}

func (s GMSigner) BytesToPub(pub []byte) (ECCPublicKey, error) {
	return new(GMPublicKey).FromBytes(pub)
}

func (s GMSigner) PubFromNodeId(id []byte) []byte {
	// 最安全的方法是先反解为ECCPublicKey，再将其转换为[]byte。但是因为转换都使用
	// elliptic.Marshal/Unmarshal，所以这里为了节省中间转换，直接使用elliptic中的参数进行转换
	pk := make([]byte, gmPubSize)
	pk[0] = 4
	copy(pk[1:], id[:])
	return pk
}

func (s GMSigner) PubToNodeIdBytes(pub []byte) ([]byte, error) {
	id := make([]byte, 64)
	if len(pub)-1 != len(id) {
		return id, fmt.Errorf("need %d bytes, got %d bytes", len(id)+1, len(pub))
	}
	copy(id[:], pub[1:])
	return id, nil
}

func (s GMSigner) Hasher() hash.Hash {
	return sm3.New()
}

func (s GMSigner) LengthOfPublicKey() int {
	return gmPubSize
}

func (s GMSigner) LengthOfPrivateKey() int {
	return gmPrivSize
}

func (s GMSigner) LengthOfSignature() int {
	return gmSigSize
}

func (s GMSigner) LengthOfHash() int {
	return HashLength
}

func (s GMSigner) String() string {
	return fmt.Sprintf("GM(sk:%d pk:%d sig:%d hash:%d)",
		s.LengthOfPrivateKey(), s.LengthOfPublicKey(), s.LengthOfSignature(), s.LengthOfHash())
}

type GMPublicKey sm2.PublicKey

func (g *GMPublicKey) ToECDSA() *ecdsa.PublicKey {
	return &ecdsa.PublicKey{Curve: g.Curve, X: math.CopyBigInt(g.X), Y: math.CopyBigInt(g.Y)}
}

func (g *GMPublicKey) FromECDSA(key *ecdsa.PublicKey) ECCPublicKey {
	g.Curve = key.Curve
	g.X = math.CopyBigInt(key.X)
	g.Y = math.CopyBigInt(key.Y)
	return g
}

func (g *GMPublicKey) ByteSize() int {
	return gmPubSize
}

func (g *GMPublicKey) ToBytes() []byte {
	if g == nil || g.X == nil || g.Y == nil {
		return nil
	}
	return elliptic.Marshal(g.Curve, g.X, g.Y)
}

func (g *GMPublicKey) FromBytes(pub []byte) (ECCPublicKey, error) {
	x, y := elliptic.Unmarshal(sm2.P256Sm2(), pub)
	if x == nil {
		return nil, errors.New("invalid sm2 public key")
	}
	g.Curve = sm2.P256Sm2()
	g.X = x
	g.Y = y
	return g, nil
}

func (g *GMPublicKey) ToNodeIDBytes() []byte {
	nid := make([]byte, 64)
	bs := g.ToBytes()
	if len(bs) == 0 {
		return nid
	}

	copy(nid[:], bs[1:])
	return nid
}

func (g *GMPublicKey) FromBytesNodeID(id []byte) ECCPublicKey {
	bs := make([]byte, secpPubSize)
	bs[0] = 4
	copy(bs[1:], id[:])
	key, _ := g.FromBytes(bs)
	return key
}

func (g *GMPublicKey) ToAddress() []byte {
	return g.PubkeyToAddress()
}

func (g *GMPublicKey) PubkeyToAddress() []byte {
	bs := g.ToBytes()
	h := g.Hash256s(bs[1:])
	if len(h) > 20 {
		h = h[len(h)-20:]
	}
	a := make([]byte, 20)
	copy(a[20-len(h):], h)
	return a
}

func (g *GMPublicKey) Hash256s(in ...[]byte) []byte {
	hasher := sm3.New()
	for _, b := range in {
		hasher.Write(b)
	}
	return hasher.Sum(nil)
}

func (g *GMPublicKey) VrfProofToHash(m, proof []byte) (index [32]byte, err error) {
	return VrfProofToHash(g, m, proof)
}

func (g *GMPublicKey) VrfVerify(m, proof []byte, index [32]byte) bool {
	return VrfVerify(g, m, proof, index)
}

type GMPrivateKey sm2.PrivateKey

func (g *GMPrivateKey) Public() crypto.PublicKey {
	return (*GMPublicKey)(&g.PublicKey)
}

func (g *GMPrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	return Sm2Sign(digest, (*sm2.PrivateKey)(g))
}

func (g *GMPrivateKey) GetPublicKey() ECCPublicKey {
	return (*GMPublicKey)(&g.PublicKey)
}

func (g *GMPrivateKey) ToECDSA() *ecdsa.PrivateKey {
	pub := ecdsa.PublicKey{Curve: g.PublicKey.Curve, X: math.CopyBigInt(g.PublicKey.X), Y: math.CopyBigInt(g.PublicKey.Y)}
	return &ecdsa.PrivateKey{PublicKey: pub, D: math.CopyBigInt(g.D)}
}

func (g *GMPrivateKey) FromECDSA(key *ecdsa.PrivateKey) ECCPrivateKey {
	g.PublicKey = sm2.PublicKey{Curve: key.Curve, X: math.CopyBigInt(key.X), Y: math.CopyBigInt(key.Y)}
	g.D = math.CopyBigInt(key.D)
	return g
}

func (g *GMPrivateKey) ByteSize() int {
	return gmPrivSize
}

func (g *GMPrivateKey) ToBytes() []byte {
	if g == nil {
		return nil
	}
	return PaddedBigBytes(g.D, g.Params().BitSize/8)
}

func (g *GMPrivateKey) FromBytes(priv []byte) (ECCPrivateKey, error) {
	g.PublicKey.Curve = sm2.P256Sm2()
	g.D = new(big.Int).SetBytes(priv)
	g.PublicKey.X, g.PublicKey.Y = g.PublicKey.Curve.ScalarBaseMult(priv)
	if g.PublicKey.X == nil {
		return nil, errors.New("invalid private key")
	}
	return g, nil
}

func (g *GMPrivateKey) VrfEval(m []byte) (index [32]byte, proof []byte) {
	return VrfEval(g, m)
}
