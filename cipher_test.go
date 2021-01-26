package cipher

import (
	"math/big"
	"testing"
)

func TestGMPoint(t *testing.T) {
	gm := NewCipher(GMSM)
	sk, err := gm.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("private key: %x", sk.ToBytes())

	A, _ := new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC", 16)

	pk := sk.GetPublicKey().ToECDSA()

	y2 := new(big.Int).Mul(pk.Y, pk.Y)
	y2.Mod(y2, pk.Curve.Params().P)

	x3 := new(big.Int).Mul(pk.X, pk.X)
	x3.Mul(x3, pk.X)
	ax := new(big.Int).Mul(A, pk.X)
	x3.Add(x3, ax)
	x3.Add(x3, pk.Curve.Params().B)
	x3.Mod(x3, pk.Curve.Params().P)

	if x3.Cmp(y2) == 0 {
		t.Logf("Y2=%x, X3+aX+b=%x, check", y2.Bytes(), x3.Bytes())
	} else {
		t.Fatalf("Y2=%x, X3+aX+b=%x, failed", y2.Bytes(), x3.Bytes())
	}

	if pk.IsOnCurve(pk.X, pk.Y) {
		t.Logf("X:%x Y:%x is on curve", pk.X, pk.Y)
	} else {
		t.Fatalf("X:%x Y:%x is not on curve", pk.X, pk.Y)
	}
}

func TestCipher(t *testing.T) {
	allCipherFunc(t, NewCipher(SECP256K1SHA3))
	allCipherFunc(t, NewCipher(GMSM))
}

func allCipherFunc(t *testing.T, cipher Cipher) {
	name := cipher.Name()

	// generate and transform
	sk, err := cipher.GenerateKey()
	if err != nil {
		t.Fatalf("[%s] generate key failed: %v", name, err)
	}

	pk := sk.GetPublicKey()

	priv := cipher.PrivToBytes(sk)
	pub := cipher.PubToBytes(pk)
	t.Logf("[%s] key generated: private:%x public:%x", name, priv, pub)

	pk1, err := cipher.BytesToPub(pub)
	if err != nil {
		t.Fatalf("[%s] %x to public key failed: %v", name, pub, err)
	} else {
		t.Logf("[%s] public key %x -> %v ok", name, pub, pk1)
	}
	sk1, err := cipher.BytesToPriv(priv)
	if err != nil {
		t.Fatalf("[%s] %x to private key failed: %v", name, priv, err)
	} else {
		t.Logf("[%s] private key %x -> %v ok", name, priv, sk1)
	}

	text := "this is a test"

	// hash
	hasher := cipher.Hasher()
	hasher.Write([]byte(text))
	hashOfText := hasher.Sum(nil)
	t.Logf("[%s] Hash(%x) = %x", name, []byte(text), hashOfText)

	// sign
	sig, err := cipher.Sign(priv, hashOfText)
	if err != nil {
		t.Fatalf("[%s] sign(%x) failed: %v", name, hashOfText, err)
	} else {
		t.Logf("[%s] sign(%x)=%x", name, hashOfText, sig)
	}

	// verify
	if cipher.Verify(pub, hashOfText, sig) {
		t.Logf("[%s] sig verify ok", name)
	} else {
		t.Fatalf("[%s] sig verify failed", name)
	}
}
