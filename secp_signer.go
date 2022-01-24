package cipher

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"hash"
	"io"
	"math/big"

	"github.com/ThinkiumGroup/go-cipher/math"
	"github.com/ThinkiumGroup/go-ecrypto/secp256k1"
	"github.com/ThinkiumGroup/go-ecrypto/sha3"
)

const (
	secpPubSize  = 65 // ((Params().BitSize + 7) >> 3)*2 + 1
	secpPrivSize = 32 // (Params().BitSize + 7) >> 3
	secpSigSize  = 65
)

// create a signer of the specified type
func NewSecpCipher() Cipher {
	return new(Secp256k1Signer)
}

type Secp256k1Signer struct{}

func (s Secp256k1Signer) Name() string {
	return SECP256K1SHA3
}

func (s Secp256k1Signer) GenerateKey() (priv ECCPrivateKey, err error) {
	pv, err := ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return (*Secp256k1PrivateKey)(pv), nil
}

func (s Secp256k1Signer) Sign(priv []byte, hash []byte) (sig []byte, err error) {
	key, err := s.BytesToPriv(priv)
	if err != nil {
		return nil, err
	}
	return Sign(hash, key.ToECDSA())
}

func (s Secp256k1Signer) Verify(pub []byte, hash []byte, sig []byte) bool {
	p := pub
	if len(pub) == 0 {
		var err error
		p, err = secp256k1.RecoverPubkey(hash, sig)
		if err != nil {
			return false
		}
	}
	if len(p) != s.LengthOfPublicKey() || len(sig) != s.LengthOfSignature() {
		return false
	}
	return VerifySignature(p, hash, sig[:64])
}

func (s Secp256k1Signer) RecoverPub(hash, sig []byte) ([]byte, error) {
	return secp256k1.RecoverPubkey(hash, sig)
}

func (s Secp256k1Signer) PrivToBytes(priv ECCPrivateKey) []byte {
	return priv.ToBytes()
}

func (s Secp256k1Signer) PubToBytes(pub ECCPublicKey) []byte {
	return pub.ToBytes()
}

func (s Secp256k1Signer) BytesToPriv(d []byte) (ECCPrivateKey, error) {
	return new(Secp256k1PrivateKey).FromBytes(d)
}

func (s Secp256k1Signer) BytesToPub(pub []byte) (ECCPublicKey, error) {
	return new(Secp256k1PublicKey).FromBytes(pub)
}

func (s Secp256k1Signer) PubFromNodeId(nid []byte) []byte {
	// 最安全的方法是先反解为ECCPublicKey，再将其转换为[]byte。但是因为转换都使用
	// elliptic.Marshal/Unmarshal，所以这里为了节省中间转换，直接使用elliptic中的参数进行转换
	pk := make([]byte, secpPubSize)
	pk[0] = 4
	copy(pk[1:], nid[:])
	return pk
}

func (s Secp256k1Signer) PubToNodeIdBytes(pub []byte) ([]byte, error) {
	id := make([]byte, 64)
	if len(pub)-1 != len(id) {
		return id, fmt.Errorf("need %d bytes, got %d bytes", len(id)+1, len(pub))
	}
	copy(id[:], pub[1:])
	return id, nil
}

func (s Secp256k1Signer) Hasher() hash.Hash {
	return sha3.NewKeccak256()
}

func (s Secp256k1Signer) LengthOfPublicKey() int {
	return secpPubSize
}

func (s Secp256k1Signer) LengthOfPrivateKey() int {
	return secpPrivSize
}

func (s Secp256k1Signer) LengthOfSignature() int {
	return secpSigSize
}

func (s Secp256k1Signer) LengthOfHash() int {
	return HashLength
}

func (s Secp256k1Signer) String() string {
	return fmt.Sprintf("Secp256k1(sk:%d pk:%d sig:%d hash:%d)",
		s.LengthOfPrivateKey(), s.LengthOfPublicKey(), s.LengthOfSignature(), s.LengthOfHash())
}

type Secp256k1PublicKey ecdsa.PublicKey

func (p *Secp256k1PublicKey) ToECDSA() *ecdsa.PublicKey {
	return (*ecdsa.PublicKey)(p)
}

func (p *Secp256k1PublicKey) FromECDSA(key *ecdsa.PublicKey) ECCPublicKey {
	p.Curve = key.Curve
	p.X = math.CopyBigInt(key.X)
	p.Y = math.CopyBigInt(key.Y)
	return p
}

func (p *Secp256k1PublicKey) ByteSize() int {
	return secpPubSize
}

func (p *Secp256k1PublicKey) ToBytes() []byte {
	if p == nil || p.X == nil || p.Y == nil {
		return nil
	}
	return elliptic.Marshal(p.Curve, p.X, p.Y)
}

func (p *Secp256k1PublicKey) FromBytes(pub []byte) (ECCPublicKey, error) {
	x, y := elliptic.Unmarshal(secp256k1.S256(), pub)
	if x == nil {
		return nil, errors.New("invalid secp256k1 public key")
	}
	p.Curve = secp256k1.S256()
	p.X = x
	p.Y = y
	return p, nil
}

func (p *Secp256k1PublicKey) ToNodeIDBytes() []byte {
	nid := make([]byte, 64)
	bs := p.ToBytes()
	if len(bs) == 0 {
		return nid
	}
	copy(nid[:], bs[1:])
	return nid
}

func (p *Secp256k1PublicKey) FromBytesNodeID(id []byte) ECCPublicKey {
	bs := make([]byte, secpPubSize)
	bs[0] = 4
	copy(bs[1:], id[:])
	key, _ := p.FromBytes(bs)
	return key
}

func (p *Secp256k1PublicKey) ToAddress() []byte {
	return p.PubkeyToAddress()
}

func (p *Secp256k1PublicKey) PubkeyToAddress() []byte {
	bs := p.ToBytes()
	h := p.Hash256s(bs[1:])
	if len(h) > 20 {
		h = h[len(h)-20:]
	}
	a := make([]byte, 20)
	copy(a[20-len(h):], h)
	return a
}

func (p *Secp256k1PublicKey) Hash256s(in ...[]byte) []byte {
	hasher := sha3.NewKeccak256()
	for _, b := range in {
		hasher.Write(b)
	}
	return hasher.Sum(nil)
}

func (p *Secp256k1PublicKey) VrfProofToHash(m, proof []byte) (index [32]byte, err error) {
	return VrfProofToHash(p, m, proof)
}

func (p *Secp256k1PublicKey) VrfVerify(m, proof []byte, index [32]byte) bool {
	return VrfVerify(p, m, proof, index)
}

type Secp256k1PrivateKey ecdsa.PrivateKey

func (p *Secp256k1PrivateKey) Public() crypto.PublicKey {
	return (*Secp256k1PublicKey)(&p.PublicKey)
}

func (p *Secp256k1PrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	return Sign(digest, (*ecdsa.PrivateKey)(p))
}

func (p *Secp256k1PrivateKey) GetPublicKey() ECCPublicKey {
	return (*Secp256k1PublicKey)(&p.PublicKey)
}

func (p *Secp256k1PrivateKey) ToECDSA() *ecdsa.PrivateKey {
	return (*ecdsa.PrivateKey)(p)
}

func (p *Secp256k1PrivateKey) FromECDSA(key *ecdsa.PrivateKey) ECCPrivateKey {
	p.PublicKey = ecdsa.PublicKey{Curve: key.Curve, X: math.CopyBigInt(key.X), Y: math.CopyBigInt(key.Y)}
	p.D = math.CopyBigInt(key.D)
	return p
}

func (p *Secp256k1PrivateKey) ByteSize() int {
	return secpPrivSize
}

func (p *Secp256k1PrivateKey) ToBytes() []byte {
	if p == nil {
		return nil
	}
	return PaddedBigBytes(p.D, p.Params().BitSize/8)
}

func (p *Secp256k1PrivateKey) FromBytes(priv []byte) (ECCPrivateKey, error) {
	p.PublicKey.Curve = secp256k1.S256()
	p.D = new(big.Int).SetBytes(priv)
	if p.D.Cmp(secp256k1N) >= 0 {
		return nil, errors.New("invalide private key, >=N")
	}
	if p.D.Sign() <= 0 {
		return nil, errors.New("invalid private key, zero or negative")
	}
	p.PublicKey.X, p.PublicKey.Y = p.PublicKey.Curve.ScalarBaseMult(priv)
	if p.PublicKey.X == nil {
		return nil, errors.New("invalid private key")
	}
	return p, nil
}

func (p *Secp256k1PrivateKey) VrfEval(m []byte) (index [32]byte, proof []byte) {
	return VrfEval(p, m)
}

func (p *Secp256k1PrivateKey) GenerateShared(k ECCPublicKey, skLen, macLen int) (sk []byte, err error) {
	pub := k.ToECDSA()
	if p.PublicKey.Curve != pub.Curve {
		return nil, ErrInvalidCurve
	}
	if skLen+macLen > MaxSharedKeyLength(k) {
		return nil, ErrSharedKeyTooBig
	}

	x, _ := pub.Curve.ScalarMult(pub.X, pub.Y, p.D.Bytes())
	if x == nil {
		return nil, ErrSharedKeyIsPointAtInfinity
	}

	sk = make([]byte, skLen+macLen)
	skBytes := x.Bytes()
	copy(sk[len(sk)-len(skBytes):], skBytes)
	return sk, nil
}
