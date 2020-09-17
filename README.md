# zed25519

**zed25519** (**Z**ooBC **Ed25519**, or just *zed*) is a small utility library for performing common cryptographic tasks with Ed25519 keypairs written in Golang. It can be imported in any Go project like this:

    import "github.com/zoobc/zed25519/zed"


## Secret and Public

zed manages keypairs with two small helper structs called *Secret* and *Public*.

If you have (or generate) a normal Ed25519 32-byte seed / private key called *mySeed*, you can turn it into a *Secret*:

    var mySecret *Secret = zed.SecretFromSeed(mySeed[:])

Then you can get the corresponding *Public*:

    var myPublic *Public = mySecret.Public()

If you want the normal Ed25519-formatted public key, just get it with the *Key* function:

    var publicKey [32]byte = myPublic.Key()

If you have a 32-byte Ed25519 public key from elsewhere, say *alice's* public key, you can convert it into a *Public* also:

    var alicePublic *Public = zed.PublicFromKey(alicePublicKey[:])

One of these two objects, a *Secret* or a *Public*, will be used to perform most operations with zed.


## Digital Signatures

## Verifiable Random Function (VRF)