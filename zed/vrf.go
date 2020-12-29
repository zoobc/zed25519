// ZooBC zed25519
//
// Copyright © 2020 Quasisoft Limited - Hong Kong
//
// ZooBC is architected by Roberto Capodieci & Barton Johnston
//             contact us at roberto.capodieci[at]blockchainzoo.com
//             and barton.johnston[at]blockchainzoo.com
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
package zed

import (
	"bytes"
	"crypto/sha512"
)

//  TODO: Explain VRF, and Signal VRF
//
//  ...
//
//  CHANGES FROM VXED25519 VRF ALGORITHM:
//
//  - Signal's VRF uses keys/points X25519, which is isomorphic to Ed25519 but
//    in Montgomery form instead of Edwards form. This implementation does math
//    on the Ed25519 Edwards form of the curve, so that it is directly
//    compatible with Ed25519 keypairs with no modifications.
//
//  - Signal's VRF uses a hash-to-point function called "Elligator 2", designed
//    by Dan Bernstein (the original creator of Ed25519), which is an efficient
//    and constant-time function. This implementation uses a guess-and-check
//    hash-to-point function, which is secure, but less efficient and not
//    constant-time. Not being constant-time is a security vulnerability only
//    if the hash-to-point function is performed on *secret* information,
//    whereas here it is used on public information availiable to both the
//    signer and valiidator, so the only downside is a lower efficiency.
//
//  - The hash-to-point function in this implementation implicitly multiplies
//    the resulting point by the Ed25519 cofactor (8), to ensure that the result
//    is always in the same subgroup as the base point. Ed25519 already ensures
//    that the private scalar a is a multiple of this cofactor, therefore
//    V = (a * Bv) is guaranteed already to be in the expected subgroup.
//		Therefore to generate the VRF output, we use V directly, instead of cV.
//
//  - Signal's VRF takes an input of random bytes as a nonce to generate the
//    value r (which must remain secret.) It combines this nonce with other
//    deterministic information based on the message and the public key
//    to generate the final nonce used in signing. There is some debate about
//    which way is safer (purely-deterministic or with-randomness.) This
//    implementation uses a purely deterministic approach, therefore no nonce
//    is passed in the function signature.
//
//  - In Signal's VRF, the output value has size 2b (512 bits), but it is the
//    hash of point V, which may only take on approximately 2^252 unique values.
//    In order not to misrepresent the amount of information in the result, this
//    implementation only returns the first 256 bits of the hash of V as the
//    output y.
//
//  REFERENCES:
//
//    [1] Trevor Perrin
//        "The XEdDSA and VXEdDSA Signature Schemes"
//        https://signal.org/docs/specifications/xeddsa
//

// VrfEval accepts an input x of arbitrary length, along with a Secret Key sk,
// and produces a 32-byte deterministic pseudo-random output y, along wiith
// a 96-byte "proof" that y is the exact correct output for the input pair
// (sk, x). The output y cannot be predicted by any party who does not possess
// the secret key sk, but given the "proof", can be verified by any party which
// possesses the corresponding public key.
func (sk *Secret) VrfEval(x []byte) (VrfResult, VrfProof) {

	// sha512 instance, result buffer
	var hash = sha512.New()
	var res Buffer512

	// get private scalar "a", prefix "p", and public point "A" from Secret
	var a = sk.Scalar()
	var p = sk.Prefix()
	var A = sk.Public().Point()

	// As = compress(A)
	var As Buffer256
	CompressPoint(&As, &A)

	// Bv = hashToPoint(As || x)
	var Bv Point
	var As_x = make([]byte, 32+len(x))
	copy(As_x[:32], As[:])
	copy(As_x[32:], x[:])
	HashToPointVartime(&Bv, As_x[:])

	// V = a * Bv
	var V Point
	ScalarMultPointVartime(&V, &a, &Bv) // WARNING: VARTIME ALGO USED ON PRIVATE DATA

	// Vs = compress(V)
	var Vs Buffer256
	CompressPoint(&Vs, &V)

	// r = sha512(p || Vs) % q
	var r Scalar
	hash.Reset()
	hash.Write(p[:])
	hash.Write(Vs[:])
	hash.Sum(res[:0])
	ScalarReduce512(&r, &res)

	// R = r * B
	var R Point
	ScalarMultBase(&R, &r)

	// Rs = compress(R)
	var Rs Buffer256
	CompressPoint(&Rs, &R)

	// Rv = r * Bv
	var Rv Point
	ScalarMultPointVartime(&Rv, &r, &Bv)

	// Rvs = compress(Rv)
	var Rvs Buffer256
	CompressPoint(&Rvs, &Rv)

	// h = sha512(As || Vs || Rs || Rvs || x) % q
	var h Scalar
	hash.Reset()
	hash.Write(As[:])
	hash.Write(Vs[:])
	hash.Write(Rs[:])
	hash.Write(Rvs[:])
	hash.Write(x[:])
	hash.Sum(res[:0])
	ScalarReduce512(&h, &res)

	// s = (r + ha) % q
	var s Scalar
	ScalarMultScalarAddScalar(&s, &h, &a, &r)

	// cV = cofactor * V
	var cV Point
	PointClearCofactor(&cV, &V)

	// cVs = compress(cV)
	var cVs Buffer256
	CompressPoint(&cVs, &cV)

	// y = sha512(cVs)[:32]
	var y VrfResult
	hash.Reset()
	hash.Write(cVs[:])
	hash.Sum(res[:0])
	copy(y[:], res[:32])

	// proof = (Vs || h || s)
	var proof VrfProof
	copy(proof[:32], Vs[:])
	copy(proof[32:64], h[:])
	copy(proof[64:], s[:])

	return y, proof
}

// VrfVerify accepts an input x of arbitrary length, a Public Key pk, and a
// 96-byte "proof" produced by the owner of the corresponding secret key sk.
// VrfVerify outputs a 32-byte result y, and a verification result bool (note
// that y will be 32 zero-bytes if the validation fails.)
func (pk *Public) VrfVerify(x, proof []byte) (VrfResult, bool) {

	// all-zeroes result for validation failure
	var zeros VrfResult

	// sha512 instance, result buffer
	var hash = sha512.New()
	var res Buffer512

	// get public point "A", and its byte encoding, from the Public
	var A = pk.Point()
	var As = pk.Key()

	// Vs = proof[:32]
	var Vs Buffer256
	copy(Vs[:], proof[:32])

	// V = decompress(Vs), or fail
	var V Point
	if !DecompressPoint(&V, &Vs) {
		return zeros, false
	}

	// h = proof[32:64]
	var h Scalar
	copy(h[:], proof[32:64])
	if !ValidScalar(&h) {
		return zeros, false
	}

	// s = proof[64:]
	var s Scalar
	copy(s[:], proof[64:])
	if !ValidScalar(&s) {
		return zeros, false
	}

	// Bv = hashToPoint(As || x)
	var Bv Point
	var As_x = make([]byte, 32+len(x))
	copy(As_x[:32], As[:])
	copy(As_x[32:], x[:])
	HashToPointVartime(&Bv, As_x[:])

	// I = "point at infinity" (group operation identity element)
	var I Point
	PointIdentity(&I)

	// cA = cofactor * A
	var cA Point
	PointClearCofactor(&cA, &A)

	// if cA == I, fail
	if PointEqual(&cA, &I) {
		return zeros, false
	}

	// cV = cofactor * V
	var cV Point
	PointClearCofactor(&cV, &V)

	// if cV == I, fail
	if PointEqual(&cV, &I) {
		return zeros, false
	}

	// cBv = cofactor * Bv
	var cBv Point
	PointClearCofactor(&cBv, &Bv)

	// if cBv == I, fail
	if PointEqual(&cBv, &I) {
		return zeros, false
	}

	// sB = s * B
	var sB Point
	ScalarMultBase(&sB, &s)

	// hA = h * A
	var hA Point
	ScalarMultPointVartime(&hA, &h, &A)

	// R = sB - hA
	var R Point
	PointSub(&R, &sB, &hA)

	// Rs = compress(R)
	var Rs Buffer256
	CompressPoint(&Rs, &R)

	// sBv = s * Bv
	var sBv Point
	ScalarMultPointVartime(&sBv, &s, &Bv)

	// hV = h * V
	var hV Point
	ScalarMultPointVartime(&hV, &h, &V)

	// Rv = sBv - hV
	var Rv Point
	PointSub(&Rv, &sBv, &hV)

	// Rvs = compress(Rv)
	var Rvs Buffer256
	CompressPoint(&Rvs, &Rv)

	// hCheck = sha512(As || Vs || Rs || Rvs || x) % q
	var hCheck Scalar
	hash.Write(As[:])
	hash.Write(Vs[:])
	hash.Write(Rs[:])
	hash.Write(Rvs[:])
	hash.Write(x[:])
	hash.Sum(res[:0])
	ScalarReduce512(&hCheck, &res)

	// if h != hCheck, fail
	if !bytes.Equal(h[:], hCheck[:]) {
		return zeros, false
	}

	// cVs = compress(cV)
	var cVs Buffer256
	CompressPoint(&cVs, &cV)

	// y = sha512(cVs)[:32]
	var y VrfResult
	hash.Reset()
	hash.Write(cVs[:])
	hash.Sum(res[:0])
	copy(y[:], res[:32])

	// verified
	return y, true
}
