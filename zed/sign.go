package zed

import (
	"crypto/sha512"
)

//
//  TODO: Revisit this text, in relation to new goals for this codebase.
//
//  This is a "no tricks up my sleeve" implementation of Ed25519 signatures,
//  using the base software implementation of Ed25519 signatures from the
//  Golang standard library, which itself is a port of the highly optimized
//  "ref10" implementation written by Ed25519's creator, Dan Bernstein.
//
//  This implementation cleans up the variable names, type names, and
//  execution order to more closely resemble the original pseudocode
//  in the Ed25519 RFC spec, and un-does some clever optimizations
//  in the ref10 implementation to make the logic more transparent.
//
//  This implementation is provided as a reference to experiment with
//  the Ed25519 signing and verification algorithms, and are not as
//  efficient as the Golang standard library, which should be used for
//  most practical cryptosystem implementations.
//
//  This implementation may also be used in the case that you wish to supply
//  supply a custom value for "r" when creating a digital signature,
//  instead of deriving it deterministically from the message and the public
//  key, as per the spec. Most implementations do not let you do this.
//
//  WARNING: ONLY USE A CUSTOM R VALUE IF YOU REALLY KNOW WHAT YOU ARE DOING.
//  If a key creates signatures on any 2 messages with the same "r" value,
//  the two signatures can be used to compute the private key (!!!). That's
//  the whole reason they made "r" deterministic in the first place. But here
//  it is for you to shoot yourself in the foot if you want. :)
//
//  REFERENCES:
//    [1] Edwards-Curve Digital Signature Algorithm (EdDSA)
//        https://tools.ietf.org/html/rfc8032
//

// Sign produces a standard Ed25519 signature by the Secret Key sk on the
// message msg. Such a valid signature on msg can only be produced by a party
// holding sk, although it can be verified by any party holding the
// corresponding Public Key.
func (sk *Secret) Sign(msg []byte) Signature {

	// sha512 instance, result buffer
	var hash = sha512.New()
	var res Buffer512

	// Take private scalar "a", prefix "p", and public point "A" from ISecret object
	var a = sk.Scalar()
	var p = sk.Prefix()
	var A = sk.Public().Point()

	// As = compress(A)
	var As Buffer256
	CompressPoint(&As, &A)

	// r = sha512(p || m) % q
	var r Scalar
	hash.Reset()
	hash.Write(p[:])
	hash.Write(msg)
	hash.Sum(res[:0])
	ScalarReduce512(&r, &res)

	// R = r * G
	var R Point
	ScalarMultBase(&R, &r)

	// Rs = compress(R)
	var Rs Buffer256
	CompressPoint(&Rs, &R)

	// h = sha512(Rs || As || m) % q
	var h Scalar
	hash.Reset()
	hash.Write(Rs[:])
	hash.Write(As[:])
	hash.Write(msg[:])
	hash.Sum(res[:0])
	ScalarReduce512(&h, &res)

	// s = (r + ha) % q
	var s Scalar
	ScalarMultScalarAddScalar(&s, &h, &a, &r)

	// sig = Rs || s
	var sig Signature
	copy(sig[:], Rs[:])
	copy(sig[32:], s[:])

	return sig
}

// Verify checks whether the signature sig on the message msg is valid for
// the Public Key pk, proving it must have been produced by a party which
// holds the corresponding Secret Key.
func (pk *Public) Verify(msg, sig []byte) bool {

	// if sig length != 64, or bits incorrect, fail
	if len(sig) != 64 || sig[63]&224 != 0 {
		return false
	}

	// init sha512 instance, result buffer
	var hash = sha512.New()
	var res Buffer512

	// Get As and A from public key object
	var As = pk.Key()
	var A = pk.Point()

	// Rs = sig[:32]
	var Rs Buffer256
	copy(Rs[:], sig[:32])

	// R = decompress(Rs), or fail
	var R Point
	if !DecompressPoint(&R, &Rs) {
		return false
	}

	// s = sig[32:]
	var s Scalar
	copy(s[:], sig[32:])

	// if s >= q, fail
	if !ValidScalar(&s) {
		return false
	}

	// h = sha512(Rs || As || m) % q
	var h Scalar
	hash.Write(Rs[:])
	hash.Write(As[:])
	hash.Write(msg[:])
	hash.Sum(res[:0])
	ScalarReduce512(&h, &res)

	// sB = s * G
	var sB Point
	ScalarMultBase(&sB, &s)

	// hA = h * A
	var hA Point
	ScalarMultPointVartime(&hA, &h, &A)

	// RphA = R + hA
	var RphA Point
	PointAdd(&RphA, &R, &hA)

	// valid if: sB == R + hA
	return PointEqual(&sB, &RphA)
}
