package zed

import (
	"bytes"

	"crypto/sha512"
)

// Buffer256 is syntax sugar for a generic 32-byte (256-bit) buffer.
type Buffer256 = [32]byte

// Buffer512 is syntax sugar for a generic 64-byte (512-bit) buffer.
type Buffer512 = [64]byte

// Signature is syntax sugar for a 64-byte buffer, used in the code to indicate
// it is intended to contain an Ed25519 signature.
type Signature = [64]byte

// VrfResult is syntax sugar for a 32-byte buffer, used to indicate that a
// buffer is the output pseudo-random result of a VRF evaluation or proof.
type VrfResult = [32]byte

// VrfProof is syntax sugar for a 96-byte buffer, used to indicate that the
// buffer is a "proof" string generated by calling VrfEval, which can be used
// with VrfVerify to re-generate the VrfResult.
type VrfProof = [96]byte

// Scalar is syntax sugar for a 32-byte buffer, used to inidicate that it
// contains a "scalar" with maximum size of the group order of Ed25519.
// Usually a Scalar will be multiplied by a curve point.
type Scalar = [32]byte

// Point is syntax sugar for an ExtendedGroupElement object, one of the more
// flexible curve point representations in Golang's ref10-based implementation.
// Util functions that operate on curve points will make sure to return them
// back into this format before returning the result to caller.
type Point = ExtendedGroupElement

// ScalarReduce512 takes a 64-byte buffer and "reduces" it "mod q", producing
// a valid scalar value. When the 64-byte input is a good unbiased random
// value, then the output scalar is also a (nearly) unbiased random value.
// This is a wrapper which renames the ref10-based function "ScReduce".
func ScalarReduce512(r *Scalar, b *Buffer512) {
	ScReduce(r, b)
}

// ScalarMultScalarAddScalar is a wrapper for the ref10-based function
// "ScMulAdd", an optimized implementation of the scalar operation: (ab + c).
func ScalarMultScalarAddScalar(r, a, b, c *Scalar) {
	ScMulAdd(r, a, b, c)
}

// ScalarMultScalar performs the scalar operation (a * b). The ref10-based
// implementation does not support this operation directly, therefore
// we actually compute the equivalent (ab + 0) using the optimized function
// "ScMulAdd".
func ScalarMultScalar(r, a, b *Scalar) {
	var zero [32]byte
	ScMulAdd(r, a, b, &zero)
}

// TODO: Understand this function better.
func ValidScalar(s *Scalar) bool {
	return ScMinimal(s)
}

// CompressPoint reduces an ExtendedGroupElement Ed25519 curve point
// representation and reduces it to its 32-byte compressed canonical binary
// representation. It is a wrapper for the ref10-based function
// ExtendedGroupElement.ToBytes.
func CompressPoint(r *Buffer256, p *Point) {
	p.ToBytes(r)
}

// DecompressPoint expands the 32-byte compressed canonical binary
// representation of an Ed25519 curve point into an ExtendedGroupElement. It
// is a wrapper for the ref10-based function ExtendedGroupElement.FromBytes.
func DecompressPoint(r *Point, b *Buffer256) bool {
	return r.FromBytes(b)
}

// ToExtended is a hack that allows recovering an ExtendedGroupElement curve
// point representation from the ProjectiveGroupElement representation. It
// does this, highly inefficiently, by serializing the Projective element,
// then de-serializing the Extended element.
// bzpython: If I learn a little more about the math or study the
// deserialization function a little closer, will re-write this transform
// more efficently. It just needs to recover the Field Element "T" which is
// lost in the Projective representation.
func (p *ProjectiveGroupElement) ToExtended(r *ExtendedGroupElement) {
	var bytes [32]byte
	p.ToBytes(&bytes)
	r.FromBytes(&bytes)
}

// PointIdentity is a helper function to "zero" an ExtendedGroupElement curve
// point representation. This is a wrapper function for ExtendedGroupElement's
// "Zero" method.
func PointIdentity(r *Point) {
	r.Zero()
}

// PointNeg flips the x-axis of an ExtendedGroupElement, such that P' = -P.
func PointNeg(r, p *Point) {
	FeNeg(&r.X, &p.X)
	FeNeg(&r.T, &p.T)
}

// PointAdd is a helper function to perform the curve point operation P + Q.
// This is built using a private function from the ref10-based implementation
// called "geAdd", which takes an ExtendedGroupElement and a CachedGroupElement,
// and outputs a CompletedGroupElement, so we normalize the call signature by
// converting one of our ExtendedGroupElement inputs ito a CachedGroupElement,
// then converting the resulting CompletedGroupElement back into our normal
// ExtendedGroupElement.
func PointAdd(r, p, q *Point) {
	var rComp CompletedGroupElement
	var qCached CachedGroupElement
	q.ToCached(&qCached)
	geAdd(&rComp, p, &qCached)
	rComp.ToExtended(r)
}

// PointSub works the same way as PointAdd, using the ref10-based function
// "geSub", in order to compute P - Q. Otherwise the representation conversion
// logic is the same.
func PointSub(r, p, q *Point) {
	var rComp CompletedGroupElement
	var qCached CachedGroupElement
	q.ToCached(&qCached)
	geSub(&rComp, p, &qCached)
	rComp.ToExtended(r)
}

// ScalarMultBase is a wrapper function around the ref10-based implementation's
// "GeScalarMultBase" function, which takes a Scalar value s, and the implicit
// Ed25519 base point B, and computes s * B.
func ScalarMultBase(r *Point, s *Scalar) {
	GeScalarMultBase(r, s)
}

// ScalarMultPointVartime performs a "variable-time" multiplication of a scalar
// with an arbitrary curve point, resulting in a new curve point.
// bzpython: I just realized this is Vartime, I can't use it a few places.
func ScalarMultPointVartime(r *ExtendedGroupElement, a *[32]byte, p *ExtendedGroupElement) {
	var rProj ProjectiveGroupElement
	var zero [32]byte
	GeDoubleScalarMultVartime(&rProj, a, p, &zero)
	rProj.ToExtended(r)
}

// PointClearCofactor is a utility which multiplies a curve point by Ed25519's
// "cofactor", which is 8. This is functionally equivalent to doubling the point
// 3 times. Clearing the cofactor of a point prevents some malleability which
// would otherwise allow multiple unique points to have the same mathematical
// features modulo the group order.
func PointClearCofactor(r, p *Point) {
	var c CompletedGroupElement
	var s ProjectiveGroupElement
	p.Double(&c)
	c.ToProjective(&s)
	s.Double(&c)
	c.ToProjective(&s)
	s.Double(&c)
	c.ToExtended(r)
}

// PointEqual compares whether two points are equal. Right now it does this a
// rather silly way, by serializing both points then checking that the two
// 32-byte buffers are equal.
// bzpython: this is done because I don't know the math well enough to say
// if there are multiple "ExtendedGroupElement" representations of the same
// value or not, because this representation stores ratios between X, Y and Z
// points internally.
func PointEqual(a, b *ExtendedGroupElement) bool {
	var aBytes, bBytes [32]byte
	a.ToBytes(&aBytes)
	b.ToBytes(&bBytes)
	return bytes.Equal(aBytes[:], bBytes[:])
}

// PointCopy duplicates the data of the input Point into a new Point object.
func PointCopy(r, p *Point) {
	FeCopy(&r.X, &p.X)
	FeCopy(&r.Y, &p.Y)
	FeCopy(&r.Z, &p.Z)
	FeCopy(&r.T, &p.T)
}

//
//  Hash any byte array into a valid Ed25519 curve point, which is in the same subgroup
//  as the Ed25519 base point.
//
//  This is a VARIABLE TIME algorithm, meaning that if it is used on inputs which are
//  supposed to be secret, it can potentially reveal information about their value
//  based on how long the function takes to execute. However, when its inputs are
//  public information, then this reveals no information that the attacker does not
//  already possess.
//
//  This function is not as nice as Dan Bernstein's "Elligator 2" hash-to-point function,
//  which is constant-time and does not depend on an underlying crytographic hash function.
//
//  Basic Algorithm:
//    ib = sha512(x)
//    ib[0] = 0
//    P = nil
//    while true:
//      ob = sha512(ib || c)
//      if ( p = decompress( ob[ 0:32] ) ) break
//      if ( p = decompress( ob[32:64] ) ) break
//      ib[0]++
//    return P * 8
//
//  Intuition: initialize a 64-byte "In Buffer" (ib) with the hash of the input (x). Then set
//  the first byte of ib to 0, and consider it a counter. Then run a loop, where at each iteration
//  we store the hash of ib in a 64-byte "Out Buffer" (ob). Consier ob as 2 32-byte buffers, which
//  are each used in one attempt to decode a valid curve point. If either succeeds, keep it as "p",
//  otherwise increment the counter ib[0] and try again. Each attempt has ~50% chance of success,
//  so getting through all 512 attempts (256 values of ib[0] with 2 attempts each) without finding
//  a valid point has probability ~2^-512, which is harder than finding a hash collision (should
//  never happen in practice.) After we find a valid point, multiply it by the cofactor (8) to
//  ensure that it falls in the same subgroup as the base point, then return to caller.
//
func HashToPointVartime(r *Point, x []byte) {
	var h = sha512.New()
	var ib Buffer512
	var ob Buffer512
	var pb Buffer256
	var p Point
	h.Write(x)
	h.Sum(ib[:0])
	ib[0] = 0
	for {
		h.Reset()
		h.Write(ib[:])
		h.Sum(ob[:0])
		copy(pb[:], ob[:32])
		if DecompressPoint(&p, &pb) {
			break
		}
		copy(pb[:], ob[32:])
		if DecompressPoint(&p, &pb) {
			break
		}
		ib[0]++
	}
	PointClearCofactor(r, &p)
}
