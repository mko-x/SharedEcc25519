Ecc25519
=====

One central provider of functions Ecc25519.h
Using 64bit C implementation of Curve25519 by Matthijs van Duin
New Structure offers
- Public Key Signature generation by Edwards
- Data Signing by Edwards/SHA512
- Key Expansion (32byte to 64 byte)
- Diffie Hellman Key Agreement by Curve25519

Complete redesign based on ideas of [FredericJacobs/25519](https://github.com/FredericJacobs/25519) project.

## Usage

### Diffie Hellman

Generating a Diffie Hellman public key:

```objective-c
NSData * publicKeyDiffieHellman = [Ecc25519 keygen:keyPrivate];
```

- - -

Computing a shared secret with Diffie Hellman:

```objective-c
NSData * sharedSecret = [Ecc25519 curvePrivate:privateKey withPublicKey:publicKey];
```

- - -

### Edwards

Expand a private 32byte key to 64byte by Edwards keypair signing:

```objective-c
NSData * privateKey = [Ecc25519 expandPrivateKey:privateKey];
```

- - -

Compute the public key signature of a private key:

```objective-c
NSData * publicKeySignature = [Ecc25519 computePublicKeySignature:keyPrivate];
```

- - -

Create a signature of a message or data with a private key:

```objective-c
NSData * signature = [Ecc25519 sign:message withPrivateKey:privateKey];
```

- - -

Verify a signature of a message or data with a public key:

```objective-c
BOOL isValid = [Ecc25519 verify:signature ofMessage:message withPublicKey:publicKey]
```

- - -

## Installation

Add this line to your `Podfile`

```
pod 'Ecc25519', '~> version number'
```
## Cryptographics

Curve25519 x86 - [Adam Langley](https://www.imperialviolet.org/)’s [curve25519-donna](https://github.com/agl/curve25519-donna)

Curve25519 x64 - Matthijs van Duin, based on work by [Daniel J Bernstein](http://cr.yp.to/ecdh.html)

Edwards25519 - [Trevor Perrin](http://trevp.net/) - extracted from [Ref 10 of ed25519 and curve25519 from supercop-20140529](https://www.github.com/trevp/ref10_extract)

## Source

https://github.com/mukarev/Ecc25519

## License

GPLv3 - copy attached and online http://www.gnu.org/licenses/gpl-3.0.html
