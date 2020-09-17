package zed

import (
	"crypto/sha512"
	"strconv"
)

// Public is the working form of an Ed25519 public key.
type Public struct {
	point Point
}

// Point gets the Ed25519 curve point of the public key.
func (pk *Public) Point() Point {
	return pk.point
}

// Key gets the canonical serialized ("compressed") form of the public key,
// which is typically accepted by Ed25519 applications and protocols, in
// a 32-byte buffer.
func (pk *Public) Key() Buffer256 {
	var key Buffer256
	CompressPoint(&key, &pk.point)
	return key
}

// Secret is the workinig form of an Ed25519 priivte key.
type Secret struct {
	scalar Scalar
	prefix Buffer256
}

// Scalar gets the private "scalar" of the secret key. This is the key piece
// of data which allows valid signatures to be produced for the public key.
func (sk *Secret) Scalar() Scalar {
	return sk.scalar
}

// Prefix gets the private "prefix" of the secret key. While not strictly
// needed to produce valid signatures, this value is used in the secret
// deterministic selection of nonces for each signature produced. Leaking it
// could result in an adversary being able to compute the private scalar from
// any valid signature.
func (sk *Secret) Prefix() Buffer256 {
	return sk.prefix
}

// Public creates the corresponding public key object for this secret key.
func (sk *Secret) Public() *Public {
	var pk = &Public{}

	// point = scalar * G
	ScalarMultBase(&pk.point, &sk.scalar)

	return pk
}

// Key gets a 64-byte serialized representation of the private key data. Note,
// this is NOT in the canonical form, which either stores the 32-byte seed,
// or the seed concatenated by the 32-byte serialized public key. Instead,
// this form stores the private scalar and prefix directly, and does not
// store the original seed. This is a much more useful format for derived keys,
// for which the seed which would generate them is infeasible to find.
func (sk *Secret) Key() Buffer512 {
	var key Buffer512

	// key = scalar || prefix
	copy(key[:32], sk.scalar[:])
	copy(key[32:], sk.prefix[:])

	return key
}

// PublicFromKey is a helper function which takes the 32-byte canonical
// Ed25519 public key string and converts it into a working form.
func PublicFromKey(key []byte) *Public {

	// if secret key length != 32 bytes , panic
	if l := len(key); l != 32 {
		panic("PublicFromKey: bad public key length: " + strconv.Itoa(l))
	}

	var pk = &Public{}
	var kb Buffer256
	copy(kb[:], key[:])

	// point = decompress(key), or panic
	if !DecompressPoint(&pk.point, &kb) {
		panic("PublicFromKey: invalid point")
	}

	return pk
}

// SecretFromKey is a helper function which builds a working form of the
// Secret Key from its 64-byte serialized form.
func SecretFromKey(key []byte) *Secret {

	// if secret key length != 64 bytes, panic
	if l := len(key); l != 64 {
		panic("SecretFromKey: bad private key length: " + strconv.Itoa(l))
	}

	var sk = &Secret{}

	// (scalar || prefix) = key
	copy(sk.scalar[:], key[:32])
	copy(sk.prefix[:], key[32:])

	// TODO: Validate scalar here

	return sk
}

// SecretFromSeed is a helper function which derives a working form of the
// Secret Key from a 32-byte seed by the original Ed25519 algorithm. This
// allows full compatibility with other Ed25519 implementations.
func SecretFromSeed(seed []byte) *Secret {

	// if secret key length != 32 bytes (or 64 bytes for compatibility), panic
	if l := len(seed); (l != 32) && (l != 64) {
		panic("SecretFromSeed: bad private key length: " + strconv.Itoa(l))
	}

	var sk = &Secret{}

	// (scalar || prefix) = sha512(seed)
	var hash = sha512.New()
	var res Buffer512
	hash.Write(seed[:32])
	hash.Sum(res[:0])
	copy(sk.scalar[:], res[:32])
	copy(sk.prefix[:], res[32:])

	// clamp scalar, as per Ed25519 spec
	sk.scalar[0] &= 248
	sk.scalar[31] &= 63
	sk.scalar[31] |= 64

	return sk
}
