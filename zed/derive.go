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
//  NOTE: Uses SHA3 functions instead of SHA256/SHA512
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
//    [3] KMAC stuff
//

// Derive generates child public key from this public key for a given "index"
// string, such that the corresponding child secret key could be generated
// by calling Derive on this public key's corresponding secret with the same
// index.
func (pk *Public) Derive(index []byte) *Public {
	var npk = &Public{}

	// compute public derivation blind for (pk, index)
	var pubkey = pk.Key()
	var blind = derivationBlind(pubkey[:], nil, index, nil)

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

// Derive has two modes for Secret Keys, which we can call "public" derivation
// and "secret" derivation. "Public" derivation allows a child keypair to be
// derived for an index string such that the public key can also be derived from
// this secret's public key with the same index. "Secret" derivation takes
// an extra arbitrary byte string, "skey", and derives a new keypair for a
// given (index, skey) pair. The public key of a "secret" child key cannot be
// identified with a parent public key.
func (sk *Secret) Derive(index, skey []byte) *Secret {
	var nsk = &Secret{}

	// compute derivation blind
	var blind Scalar
	if skey == nil {
		var pubkey = sk.Public().Key()
		blind = derivationBlind(pubkey[:], nil, index, nil)
	} else {
		var scalar = sk.Scalar()
		blind = derivationBlind(nil, scalar[:], index, skey)
	}

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

// DerivationBlind is used to compute the "blind" scalar which both a public
// and private key are multiplied by to generate the new keypair.
// If hidden=true, key is expected be the private scalar of the parent
// keypair, otherwise it is expected to be the serialized public key of the
// parent keypair.
func derivationBlind(pubkey, scalar, index, skey []byte) Scalar {
	var hash = sha3.New512()

	// derive kmac key differently depending on secret or public child
	var key Buffer512
	if skey == nil {
		// key = sha3_512(public_str || pubkey)
		hash.Write([]byte("zed25519_derivation_index_public"))
		hash.Write(pubkey)
	} else {
		// key = sha3_512(private_str || scalar || skey)
		hash.Write([]byte("zed25519_derivation_index_secret"))
		hash.Write(scalar)
		hash.Write(skey)
	}
	hash.Sum(key[:0])

	// kmac = sha3_512(key || index)
	var kmac Buffer512
	hash.Reset()
	hash.Write(key[:])
	hash.Write(index)
	hash.Sum(kmac[:0])

	// blind = kmac % q
	var blind Scalar
	ScalarReduce512(&blind, &kmac)

	return blind
}
