package zed

import "crypto/sha512"

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
func (pk *Public) Derive(selector []byte) *Public {
	var npk = &Public{}
	var hash = sha512.New()
	var res Buffer512

	// h = first-half of sha512(selector)
	var h Scalar
	hash.Write(selector[:])
	hash.Sum(res[:0])
	copy(h[:], res[:32])

	// clamp h, as per Ed25519 spec
	h[0] &= 248
	h[31] &= 63
	h[31] |= 64

	// A' = h * A
	ScalarMultPointVartime(&npk.point, &h, &pk.point)
	return npk
}

// TODO: choose strategy for derivation and finish implementation.
func (sk *Secret) Derive(selector []byte) *Secret {
	var nsk = &Secret{}
	var hash = sha512.New()
	var res Buffer512

	// (h || p) = sha512(selector)
	var h Scalar
	var p Buffer256
	hash.Write(selector[:])
	hash.Sum(res[:0])
	copy(h[:], res[:32])

	// clamp h, as per Ed25519 spec
	h[0] &= 248
	h[31] &= 63
	h[31] |= 64

	// a' = h * a
	ScalarMultScalar(&nsk.scalar, &h, &sk.scalar)

	// (prefix' || _) = sha512(prefix || p)
	hash.Reset()
	hash.Write(sk.prefix[:])
	hash.Write(p[:])
	hash.Sum(res[:0])
	copy(nsk.prefix[:], res[:32])

	return nsk
}
