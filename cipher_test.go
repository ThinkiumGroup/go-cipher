package cipher

import (
	"testing"
)

func TestCipher(t *testing.T) {
	allCipherFunc(t, NewCipher(SECP256K1SHA3))
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
