package zed

import (
	"crypto/sha512"

	"golang.org/x/crypto/sha3"
)

//
//  Key derivation allows "child" keypairs to be derived deterministically from
//  "parent" keypairs.
//
//  TODO: Explain hierarchical key derivation for Ed25519 and related work...
//
//  REFERENCES:
//    [1] Nicholas Hopper
//        "Proving Security of Tor’s Hidden Service Identity Blinding Protocol"
//        https://www-users.cs.umn.edu/~hoppernj/basic-proof.pdf
//
//    [2] David Goulet, George Kadianakis, Nick Mathewson
//        "Next-Generation Hidden Services in Tor"
//        https://gitweb.torproject.org/torspec.git/tree/proposals/224-rend-spec-ng.txt#n2135
//

// TODO: choose strategy for derivation and finish implementation.
func (pk *Public) Derive(index []byte) *Public {
	var npk = &Public{}

	// compute public derivation blind for (pk, index)
	var key = pk.Key()
	var blind = DerivationBlind(&key, index, false)

	// clamp blind, as per Ed25519 spec
	blind[0] &= 248
	blind[31] &= 63
	blind[31] |= 64

	// TODO: Carefully consider effect of repeatedly applying clamp on each
	//       multiply (are we losing 3 bits each derivation level?)

	// A' = h * A
	ScalarMultPointVartime(&npk.point, &blind, &pk.point)
	return npk
}

// TODO: choose strategy for derivation and finish implementation.
func (sk *Secret) Derive(index []byte, hidden bool) *Secret {
	var nsk = &Secret{}

	// compute derivation blind
	var key Buffer256
	if hidden {
		key = sk.Scalar()
	} else {
		key = sk.Public().Key()
	}
	var blind = DerivationBlind(&key, index, hidden)

	// clamp blind, as per Ed25519 spec
	blind[0] &= 248
	blind[31] &= 63
	blind[31] |= 64

	// TODO: Carefully consider effect of repeatedly applying clamp on each
	//       multiply (are we losing 3 bits each derivation level?)

	// a' = h * a
	ScalarMultScalar(&nsk.scalar, &blind, &sk.scalar)

	// TODO: considering removing "prefix" entirely for simplicity, if secure.
	// (prefix' || _) = sha512(prefix || p)
	var hash = sha512.New()
	var res Buffer512
	var prefix = sk.Prefix()
	hash.Reset()
	hash.Write(sk.prefix[:])
	hash.Write(prefix[:])
	hash.Sum(res[:0])
	copy(nsk.prefix[:], res[:32])

	return nsk
}

//
func DerivationBlind(key *Buffer256, index []byte, hidden bool) Scalar {
	var hash = sha3.New512()
	var res Buffer512

	// select hash prefix
	var prefix []byte
	if hidden {
		prefix = []byte("zed25519_derivation_index_hidden")
	} else {
		prefix = []byte("zed25519_derivation_index_public")
	}

	// inner = sha3_512(prefix || key || selector)
	hash.Write(prefix[:])
	hash.Write(key[:])
	hash.Write(index[:])
	hash.Sum(res[:0])

	// outer = sha3_512(prefix || inner[:32] || selector)
	hash.Reset()
	hash.Write(prefix[:])
	hash.Write(res[:32])
	hash.Write(index[:])
	hash.Sum(res[:0])

	// blind = outer % q
	var blind Scalar
	ScalarReduce512(&blind, &res)

	return blind
}
