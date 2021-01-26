// Copyright (C) 2018 go-nebulas

//
// This file is part of the go-nebulas library.
//
// the go-nebulas library is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// the go-nebulas library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with the go-nebulas library.  If not, see <http://www.gnu.org/licenses/>.
//

package vrf

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"testing"

	"github.com/ThinkiumGroup/go-cipher"
)

const (
	// private key in hex
	testPrivKey = `b02b430d4a9d7120b65038452a6da3f3c716829e5be3665adf934d4798d96ed7`
	// public key in hex
	testPubKey = `04e4d0dde330c0b8d8d8b1b2071aa75c3e94f200a3d11ca1d908644eee50c8833a816dc0b2d003fc66187ef6750a56e1b3004d32e6159008400ab92f2ded7b4544`
)

//
// func TestVRFold(t *testing.T) {
//	priv := secp256k1.GeneratePrivateKey()
//	seckey, err := priv.Encoded()
//	if err != nil {
//		t.Errorf("new priv err: %v", err)
//	}
//	pk, err := priv.PublicKey().Encoded()
//	if err != nil {
//		t.Errorf("pub of new priv err: %v", err)
//	}
//	fmt.Println("1:", seckey)
//	fmt.Println("2:", pk)
//
// }

func TestVRF(t *testing.T) {
	oneTypeVrf(t, cipher.NewCipher(cipher.GMSM))
	oneTypeVrf(t, cipher.NewCipher(cipher.SECP256K1SHA3))
}

func oneTypeVrf(t *testing.T, cipher cipher.Cipher) {
	sk, _ := cipher.GenerateKey()
	pk := sk.GetPublicKey()

	m := make([]byte, 100)
	io.ReadFull(rand.Reader, m)

	// index, proof := sk.Evaluate(m)
	index, proof := sk.VrfEval(m)
	// index2, err := pk.ProofToHash(m, proof)
	index2, err := pk.VrfProofToHash(m, proof)
	fmt.Printf("Cipher: %s\n", cipher.Name())
	fmt.Printf("m: %x\n", m)
	fmt.Printf("index: %x, proof: %x\n", index, proof)
	fmt.Printf("index2: %x\n", index2)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(index[:], index2[:]) {
		t.Errorf("verification failed")
	}
}
