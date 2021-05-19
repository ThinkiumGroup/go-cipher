package cipher

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"testing"
)

const (
	// private key in hex
	privKey = `b02b430d4a9d7120b65038452a6da3f3c716829e5be3665adf934d4798d96ed7`
	// public key in hex
	pubKey = `04e4d0dde330c0b8d8d8b1b2071aa75c3e94f200a3d11ca1d908644eee50c8833a816dc0b2d003fc66187ef6750a56e1b3004d32e6159008400ab92f2ded7b4544`
)

var RealCipher Cipher

func HexToPrivKey(h string) (ECCPrivateKey, error) {
	bs, err := hex.DecodeString(h)
	if err != nil {
		return nil, err
	}
	return RealCipher.BytesToPriv(bs)
}
func init() {
	RealCipher = NewCipher(SECP256K1SHA3)
}

func TestKeys(t *testing.T) {

	seckey, err := hex.DecodeString(privKey)
	if err != nil {
		t.Errorf("load priv err: %v", err)
	}

	// private key decoding
	sk, err := HexToPrivKey(privKey)
	if err != nil {
		t.Errorf("ecdsa err: %v", err)
	}

	// private key encoding
	encodedSecKey := sk.ToBytes()
	if !bytes.Equal(encodedSecKey, seckey) {
		t.Error("seckey encoding mismatch")
	}

	data := []byte("b10c1203d5ae6d4d069d5f520eb060f2f5fb74e942f391e7cadbc2b5148dfbcb")
	sIndex, proof := sk.VrfEval(data)

	pk := sk.GetPublicKey()

	// public key encoding
	encodedPubkey := pk.ToBytes()
	seckeyPub, err := hex.DecodeString(pubKey)
	if !bytes.Equal(seckeyPub, encodedPubkey) {
		t.Error("pubkey encoding mismatch")
	}

	// public key decoding
	decodedPubkey, err := RealCipher.BytesToPub(encodedPubkey)
	if err != nil {
		t.Errorf("pubkey decoding err: %v", err)
	}
	encodedPubkey2 := decodedPubkey.ToBytes()
	if !bytes.Equal(encodedPubkey, encodedPubkey2) {
		t.Error("pubkey decoding mismatch")
	}

	// correctness of proof
	vIndex, err := pk.VrfProofToHash(data, proof)
	if err != nil {
		t.Errorf("exec proof err: %v", err)
	}

	if !bytes.Equal(sIndex[0:], vIndex[0:]) {
		t.Errorf("verification failed")
	}
}

func TestGeneratedKey(t *testing.T) {
	sk, err := RealCipher.GenerateKey()
	if err != nil {
		t.Errorf("key generation err: %v", err)
	}
	pk := sk.GetPublicKey()

	// Test VRF
	m := make([]byte, 100)
	io.ReadFull(rand.Reader, m)

	index, proof := sk.VrfEval(m)
	index2, err := pk.VrfProofToHash(m, proof)
	fmt.Println(m)
	fmt.Println(index)
	fmt.Println(index2)
	if err != nil {
		t.Errorf("ProofToHash error: %v", err)
	}
	if !bytes.Equal(index[:], index2[:]) {
		t.Errorf("VRF verification failed")
	}

	// Test Signature
	h := make([]byte, 32)
	io.ReadFull(rand.Reader, h)
	// sig, err := sk.SignHash(h)
	// if err != nil {
	// 	t.Errorf("signing error: %v", err)
	// }
	// fmt.Println(h)
	// fmt.Println(sig)
	// if !pk.VerifyHashSig(h, sig) {
	// 	t.Error("signature verification fail")
	// }
	// // Recover pubkey from signature
	// rpk, err := RecoverPubkey(h, sig)
	// if err != nil {
	// 	t.Errorf("recover pubkey error: %v", err)
	// }
	// if !bytes.Equal(FromPubkey(pk), FromPubkey(rpk)) {
	// 	t.Errorf("recover pubkey mismatch")
	// }
}
