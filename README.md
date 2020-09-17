# zed25519

**zed25519** (**Z**ooBC **Ed25519**, or just ***zed***) is a small utility library for performing common cryptographic tasks with Ed25519 keypairs for Golang. It can be imported in any Go project like this:

    import "github.com/zoobc/zed25519/zed"


## Secret and Public

***zed*** manages keypairs with two small helper structs called *Secret* and *Public*.

If you have (or generate) a normal Ed25519 32-byte seed / private key called *mySeed*, you can turn it into a *Secret*:

    var mySecret *Secret = zed.SecretFromSeed(mySeed[:])

Then you can get the corresponding *Public*:

    var myPublic *Public = mySecret.Public()

If you want the normal Ed25519-formatted public key, just get it with the *Key* function:

    var publicKey [32]byte = myPublic.Key()

If you have a 32-byte Ed25519 public key from elsewhere, say *alice's* public key, you can convert it into a *Public* also:

    var alicePublic *Public = zed.PublicFromKey(alicePublicKey[:])

One of these two objects, a *Secret* or a *Public*, will be used to perform most operations with ***zed***.


## Digital Signatures

The original function of Ed25519 is *Digital Signatures*. 

Let's say Alice wants to sign a message with her Secret:

    var message []byte = []byte("zed is pretty cool!")
    var sig [64]byte = aliceSecret.Sign(message[:])

Bob already has Alice's public key from before, and can now verify that *sig* was produced by Alice, on the original *message*:

    var valid bool = alicePublic.Verify(message[:], sig[:])


## Verifiable Random Function (VRF)

An Ed25519 keypair can also be extended to support a *Verfiable Random Function* or *VRF*. This is similar to a digital signature, in that one party produces an unpredictable "proof" string from its Secret and an input message, such that the "proof" can then be verified by another party with the corresponding Public. However, unlike a digital signature, this "proof" encodes a deterministic pseudorandom value, which is additionally not *malleable* (meaning neither the *Prover* or *Verifier* can influence the output for a given (*Secret*, *message*) pair.)

Lets say Alice wants to evaluate the VRF for her *Secret* and some input value *x*. She can use the *VrfEval* function to get the 32-byte pseudorandom output *y* and the 96-byte *proof* of the correctness of *y*:

    var x = []byte("some input value") // the input message
    var y [32]byte // the output pseudorandom number
    var proof [96]byte // the "proof" that y is correct

    y, proof = aliceSecret.VrfEval(x[:])

Now Bob, holding only Alice's *Public*, wants to verify that Alice produced the VRF output, and compute the VRF output himself. If he has the same input *x*, and the 96-byte *proof* produced when Alice used *VrfEval*, he can use the *VrfVerify* function to compute the same 32-byte pseudorandom output *y* for himself:

    var y [32]byte = alicePublic.VrfVerfy(x[:], proof[:])


## Key Derivation

*Coming soon...*


## Key Exchange

*Coming soon...*


## Encryption

*Comming soon...*


## Proxy Re-Encryption

*Coming soon...*


# License

This repository contains 2 files (*zed/const.go* and *zed/ed25519.go*) which are reproduced exactly (except for the *package* declaration) from the Golang standard library (*golang.org/x/crypto/ed25519*). These two files remain licensed to their original authors under their original licensing terms, and are only reproduced in this repository because they are internal/inaccessible from the Go standard library. Together, they are a port of the *ref10* c implementation of the Ed25519 digital signature algorithm, which was originally written by Dan Bernstein.

All other files in this repository are copyright Quasisoft Limited, licensed for public use under the MIT License as described in the LICENSE file.