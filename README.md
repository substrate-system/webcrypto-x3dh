# webcrypto x3dh
[![tests](https://img.shields.io/github/actions/workflow/status/substrate-system/webcrypto-x3dh/nodejs.yml?style=flat-square)](https://github.com/substrate-system/webcrypto-x3dh/actions/workflows/nodejs.yml)
[![types](https://img.shields.io/npm/types/@substrate-system/webcrypto-x3dh?style=flat-square)](README.md)
[![module](https://img.shields.io/badge/module-ESM-blue?style=flat-square)](README.md)
[![semantic versioning](https://img.shields.io/badge/semver-2.0.0-blue?logo=semver&style=flat-square)](https://semver.org/)
[![install size](https://flat.badgen.net/packagephobia/install/@substrate-system/webcrypto-x3dh?cache-control=no-cache)](https://packagephobia.com/result?p=@substrate-system/webcrypto-x3dh)
[![GZip size](https://flat.badgen.net/bundlephobia/minzip/@substrate-system/webcrypto-x3dh)](https://bundlephobia.com/package/@substrate-system/x3dh)
[![license](https://img.shields.io/badge/license-Big_Time-blue?style=flat-square)](LICENSE)

X3DH for the browser. This is a typeScript implementation of X3DH, as described
in ***[Going Bark: A Furry's Guide to End-to-End Encryption](https://soatok.blog/2020/11/14/going-bark-a-furrys-guide-to-end-to-end-encryption/)***.

This uses the
[Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API),
so it works in the browser.

## Contents

<!-- toc -->

- [fork](#fork)
- [Install](#install)
- [What's This?](#whats-this)
- [Platform Independence](#platform-independence)
  * [Improved Browser Compatibility (v0.4.0)](#improved-browser-compatibility-v040)
- [Use](#use)
  * [Get Started](#get-started)
  * [Constructor Options](#constructor-options)
  * [Performing X3DH Key Exchange](#performing-x3dh-key-exchange)
  * [Receiving the Key Exchange](#receiving-the-key-exchange)
- [API Reference](#api-reference)
  * [Types](#types)
  * [Main Class](#main-class)
- [Should I Use This?](#should-i-use-this)

<!-- tocstop -->


X3DH ([Extended Triple Diffie-Hellman](https://signal.org/docs/specifications/x3dh/))
is a secure key exchange protocol for
end-to-end encrypted communication. It allows two parties to establish a
shared secret for encrypted messaging, even when one party is offline.

**This library handles key exchange only.** It returns a shared secret that you
can use with a ratcheting protocol (like [Double Ratchet](https://signal.org/docs/specifications/doubleratchet/))
for ongoing message encryption.
No session state is stored &mdash; this does key exchange only.

The standard X3DH handshake usually includes three exchanges:

1. Alice’s ephemeral key + Bob’s identity key
2. Alice’s ephemeral key + Bob’s signed prekey
3. (Optionally) Alice’s identity key + Bob’s signed prekey

These three Diffie–Hellman results are then concatenated and
passed through a KDF (key derivation function) to produce a single strong
shared secret.


## fork

This is a fork of [soatok/rawr-x3dh](https://github.com/soatok/rawr-x3dh).
Thanks `@soatok` for working in public.

## Install

```sh
npm i -S @substrate-system/webcrypto-x3dh
```

## What's This?

This library implements the [Extended Triple Diffie-Hellman](https://signal.org/docs/specifications/x3dh/)
key exchange, with a few minor tweaks:

1. Identity keys are Ed25519 public keys, not X25519 public keys.
   [See this for an explanation](https://soatok.blog/2020/11/14/going-bark-a-furrys-guide-to-end-to-end-encryption/#why-ed25519-keys-x3dh).
2. Encryption/decryption and KDF implementations are pluggable
   (assuming you implement the interface I provide), so you aren't
   married to HKDF or a particular cipher. (Although I recommend hard-coding
   it to your application!)

## Platform Independence

This library is designed to work across different JavaScript environments:

- **Browser environments** - Works with the Web Crypto API
- **Node.js** - Uses the webcrypto API in Node
- **Web Workers** - Background processing

### Improved Browser Compatibility (v0.4.0)

The library now handles Ed25519 key format differences between browsers and
Node.js automatically:
- Automatically detect and supports both raw (32-byte) and structured
  (SPKI/PKCS8) Ed25519 key formats
- Export keys in the format most compatible with the current environment
- Fallback mechanisms ensure keys work across different Web Crypto
  API implementations


## Use

See [Signal docs - 3.1. Overview](https://signal.org/docs/specifications/x3dh/#the-x3dh-protocol)

>
> X3DH has three phases:
>
>   1. Bob publishes his identity key and prekeys to a server.
>   2. Alice fetches a "prekey bundle" from the server, and uses it to send an
>      initial message to Bob.
>   3. Bob receives and processes Alice's initial message.
>


### Get Started

Use [@substrate-system/keys](https://github.com/substrate-system/keys) for
identity key management.

Alice wants to start a conversation with Bob. Bob has already published some
public keys to the server.

Every user has an identity key (IK) &mdash; a long-term, static ed25519 keypair.

At this point Bob should have published an identity key, a signed pre-key (SPK),
and a one-time pre-key (OPK).

Alice must have an identity key and an **ephemeral key** (EK), which is created
fresh for each session.

1. Alice fetches Bob's identity key, signed pre-key, and possibly
   one-time pre-key
2. Alice computes 4 Diffie-Hellman exchanges:
  1. IK_A x SPK_B
  2. EK_A x IK_B
  3. EK_A x SPK_B
  4. EK_A x OPK_B
3. Those results are combined via a KDF to produce a **shared secret**.
4. Alice sends her first encrypted message to Bob, including EK_A, her
   identity info, and the used prekey identifiers
5. Bob does the same DH calculations and derives the same shared secret.


When all is said and done, both parties have the same shared secret key
material.


* The **ephemeral keys** give us _forward secrecy_, meaning that if
  long-term keys are compromised, previous sessions remain secure.
* The pre-keys are signed, which prevents impersonation attacks.


Since messages are authenticated via ephemeral DH rather than digital
signatures on each message, a third party can’t cryptographically prove you
authored a message.

**One-time pre-keys** prevent an attacker from re-using an initial handshake to
trick you into deriving the same session key again.


#### Alice's side

```ts
import { EccKeys } from '@substrate-system/keys/ecc'
import { X3DH } from '@substrate-system/webcrypto-x3dh'

// 1. Create identity keys with @substrate-system/keys
const aliceKeys = await EccKeys.create()
await aliceKeys.persist()

// 2. Generate X25519 pre-keys
const preKeyPair = await X3DH.prekeys()

// 3. Create X3DH keys instance
//  - aliceKeys has privateWriteKey and publicWriteKey properties
//  - preKeyPair has privateKey and publicKey properties
const x3dhKeys = X3DH.X3DHKeys(aliceKeys, preKeyPair)

// 4. Initialize X3DH with keys and identity string
const x3dh = new X3DH(x3dhKeys, aliceKeys.DID)

// 5. Generate one-time keys for key exchange
const oneTimeKeyBundle = await x3dh.generateOneTimeKeys(10)

// Upload oneTimeKeyBundle to your server so others can retrieve them
// during key exchange

// 6. Perform key exchange with another user
// First, fetch the recipient's public keys from your server
const recipientKeys = await fetch('/api/keys/recipient-did').then(r => r.json())
// recipientKeys has shape: {
//   IdentityKey,
//   SignedPreKey: { Signature, PreKey },
//   OneTimeKey?
// }

const result = await x3dh.initSend('recipient-did', recipientKeys)

// Send the handshake to the recipient (via your server or direct messaging),
// so they can derive the same secret.
await sendToRecipient(result.handshakeData)

// X3DH is now complete. Use the shared secret to initialize your
// ratcheting protocol (e.g., Double Ratchet)
const doubleRatchet = new DoubleRatchet(result.sharedSecret)
```

#### Bob's side

The other side of the conversation above.

```ts
import { EccKeys } from '@substrate-system/keys/ecc'
import { X3DH } from '@substrate-system/webcrypto-x3dh'

// 1. Create identity keys with @substrate-system/keys
const bobKeys = await EccKeys.create()
await bobKeys.persist()

// 2. Generate X25519 pre-keys
const preKeyPair = await X3DH.prekeys()

// 3. Create X3DH keys instance
const x3dhKeys = X3DH.X3DHKeys(bobKeys, preKeyPair)

// 4. Initialize X3DH with keys and identity string
const x3dh = new X3DH(x3dhKeys, bobKeys.DID)

// 5. Generate one-time keys for key exchange
const oneTimeKeyBundle = await x3dh.generateOneTimeKeys(10)

// Upload oneTimeKeyBundle to your server so others can retrieve them
// during key exchange

// 6. Receive handshake data from Alice
const handshakeData = await receiveFromSender()  // Get handshake from Alice

const result = await x3dh.initReceive(handshakeData)

// X3DH is now complete. Both sides have the same shared secret.
//
// result.sharedSecret is a Uint8Array - the same value Alice has
// result.senderIdentity is Alice's DID

// Use the shared secret to initialize your ratcheting protocol
// (e.g., Double Ratchet)
const doubleRatchet = new DoubleRatchet(result.sharedSecret)
```


#### `static X3DHKeys`

```ts
class X3DH {
  static X3DHKeys (
    idKeys:{
      privateWriteKey:Ed25519SecretKey,
      publicWriteKey:Ed25519PublicKey
    },
    preKeypair:{
      privateKey:X25519SecretKey,
      publicKey:X25519PublicKey
    }
  ):X3DHKeys
}
```

#### `type X3DHKeys`

```ts
type X3DHKeys = {
  identitySecret:Ed25519SecretKey
  identityPublic:Ed25519PublicKey
  preKeySecret:X25519SecretKey
  preKeyPublic:X25519PublicKey
}
```

### Constructor Options

```ts
const x3dh = new X3DH(
  x3dhKeys,                    // X3DHKeys (required)
  identityString,              // string/DID (required)
  keyDerivationFunction        // KeyDerivationFunction (optional)
)
```

### Performing X3DH Key Exchange

Once your X3DH object has been created, you can perform key exchanges:

```ts
// Generate one-time keys for others to use
const oneTimeKeyBundle = await x3dh.generateOneTimeKeys(10)
// Upload oneTimeKeyBundle to your server so others can retrieve them
// during key exchange

// Initiate communication (sender side)
// First, fetch the recipient's public keys from your server
const recipientKeys = await fetch('/api/keys/recipient-did-string')
  .then(r => r.json())

const result = await x3dh.initSend('recipient-did-string', recipientKeys)

// result.sharedSecret is a Uint8Array you use to initialize your
//   ratcheting protocol
// result.handshakeData is sent to the recipient
```

The `recipientKeys` parameter should be an object containing the recipient's
identity key, signed pre-key, and optional one-time key.

See the definition of the `InitServerInfo` type in [src/index.ts](./src/index.ts):

```ts
type InitServerInfo = {
    IdentityKey:string;
    SignedPreKey:{
        Signature:string;
        PreKey:string;
    };
    OneTimeKey?:string;
};
```


### Receiving the Key Exchange

Derive the same secret value as the sender.

```ts
// Receive handshake (recipient side)
const result = await x3dh.initReceive(handshakeData)

// X3DH is now complete. Both sides have the same shared secret.
// result.sharedSecret is a Uint8Array - the same value the sender has
// result.senderIdentity is the sender's DID

// Use the shared secret to initialize your ratcheting protocol
// (e.g., Double Ratchet)
const doubleRatchet = new DoubleRatchet(result.sharedSecret)
```

>
> [!NOTE]  
> This library only performs the X3DH key exchange. For ongoing message
> encryption, you need to implement or use a ratcheting protocol like
> Double Ratchet with the shared secret returned from
> `initSend()` and `initReceive()`.
>

This library does not implement
[Gossamer integration](https://soatok.blog/2020/11/14/going-bark-a-furrys-guide-to-end-to-end-encryption/#identity-key-management)
for identity key management.

## API Reference

### Types

```ts
type X3DHKeys = {
    identitySecret: Ed25519SecretKey
    identityPublic: Ed25519PublicKey
    preKeySecret: X25519SecretKey
    preKeyPublic: X25519PublicKey
}

type InitServerInfo = {
    IdentityKey: string;
    SignedPreKey: {
        Signature: string;
        PreKey: string;
    };
    OneTimeKey?: string;
}

type InitSenderInfo = {
    Sender: string,
    IdentityKey: string,
    PreKey: string,
    EphemeralKey: string,
    OneTimeKey?: string
}

type InitSendResult = {
    sharedSecret: Uint8Array
    handshakeData: InitSenderInfo
}

type InitReceiveResult = {
    sharedSecret: Uint8Array
    senderIdentity: string
}
```

### Main Class

- `X3DH` - Main class for X3DH key exchange operations

#### X3DH

Main class for performing X3DH key exchanges.

**Static Methods:**

##### `X3DH.prekeys`

```ts
X3DH.prekeys():Promise<CryptoKeyPair>
```

Generate an X25519 key pair for use as pre-keys in X3DH.

**Returns:** A promise resolving to a `CryptoKeyPair` with
`privateKey` and `publicKey`.

**Example:**
```ts
const preKeyPair = await X3DH.prekeys()
```

##### `X3DH.X3DHKeys`

```ts
X3DH.X3DHKeys(
  idKeys:{
    privateWriteKey:Ed25519SecretKey,
    publicWriteKey:Ed25519PublicKey
  },
  preKeypair:{
    privateKey:X25519SecretKey,
    publicKey:X25519PublicKey
  }
):X3DHKeys
```

Helper function to construct an X3DHKeys object from identity keys and pre-keys.

**Parameters:**
- `idKeys` - Object with `privateWriteKey` and `publicWriteKey`
  (Ed25519 keys from `@substrate-system/keys`)
- `preKeypair` - Object with `privateKey` and `publicKey`
  (X25519 keys from `X3DH.prekeys()`)

**Returns:** `X3DHKeys` object for use in X3DH constructor

**Example:**
```ts
const x3dhKeys = X3DH.X3DHKeys(aliceKeys, preKeyPair)
```

**Constructor:**

##### `new X3DH`

```ts
new X3DH(
  keys:{
    identitySecret:Ed25519SecretKey
    identityPublic:Ed25519PublicKey
    preKeySecret:X25519SecretKey
    preKeyPublic:X25519PublicKey
  },
  identityString:string,
  kdf?:KeyDerivationFunction
)
```

Creates a new X3DH instance.

**Parameters:**
- `keys: X3DHKeys` (required) - Identity and pre-keys for this participant
- `identityString: string` (required) - Unique identifier (typically a DID)
  for this participant
- `kdf?: KeyDerivationFunction` (optional) - Custom key derivation function
  (defaults to `blakeKdf`)

**Example:**
```ts
const x3dh = new X3DH(x3dhKeys, aliceKeys.DID)
```

**Instance Methods:**

##### `generateOneTimeKeys`

```ts
generateOneTimeKeys(numKeys?:number):Promise<{
  signature:string
  bundle:string[]
}>
```

Generates and signs a bundle of one-time keys for use in X3DH handshakes.
Stores them locally for later retrieval during `initReceive()`.

**Parameters:**
- `numKeys?:number` (default: 100) - Number of one-time keys to generate

**Returns:** Promise resolving to `SignedBundle` with:
- `signature:string` - Hex-encoded signature over the bundle
- `bundle:string[]` - Array of hex-encoded public keys

**Example:**
```ts
const bundle = await x3dh.generateOneTimeKeys(10)
// Upload bundle to server for distribution
```

##### `initSend`

Initiates X3DH key exchange as the sender. Performs X3DH handshake and returns
the shared secret.

```ts
initSend(
  recipientIdentity:string,
  recipientKeys:{
    IdentityKey:string
    SignedPreKey:{
      Signature:string
      PreKey:string
    }
    OneTimeKey?:string
  }
):Promise<{
  sharedSecret: Uint8Array
  handshakeData: InitSenderInfo
}>
```

**Parameters:**
- `recipientIdentity:string` - DID or identifier of the recipient
- `recipientKeys:InitServerInfo` - Object containing recipient's public keys

**Returns:** Promise resolving to `InitSendResult` containing:
- `sharedSecret: Uint8Array` - The derived shared secret from X3DH
- `handshakeData: InitSenderInfo` - Handshake data to send to recipient

**Example:**
```ts
// Fetch recipient's keys from your server
const recipientKeys = await fetch('/api/keys/did:example:bob').then(r => r.json())

const result = await x3dh.initSend('did:example:bob', recipientKeys)

// result.sharedSecret is a Uint8Array to use for your ratcheting protocol
// Send result.handshakeData to the recipient
```

##### `initReceive`

Receive and process an initial handshake message from a sender. Returns the
shared secret and sender's identity.

```ts
initReceive(req:{
  Sender:string
  IdentityKey:string
  PreKey:string
  EphemeralKey:string
  OneTimeKey?:string
}):Promise<{
  sharedSecret: Uint8Array
  senderIdentity: string
}>
```

**Parameters:**
- `req:InitSenderInfo` - Handshake data received from sender

**Returns:** Promise resolving to `InitReceiveResult` containing:
- `sharedSecret: Uint8Array` - The derived shared secret from X3DH
- `senderIdentity: string` - The sender's DID

**Example:**
```ts
const result = await x3dh.initReceive(handshakeData)
console.log(`Received from ${result.senderIdentity}`)
// Use result.sharedSecret to initialize your ratcheting protocol
```

##### `signPreKey`

Sign an X25519 pre-key with an Ed25519 identity key. Use to create signed
pre-key bundles.

```ts
signPreKey(signingKey:Ed25519SecretKey, preKey:X25519PublicKey):Promise<string>
```

**Parameters:**
- `signingKey: Ed25519SecretKey` - Identity secret key for signing
- `preKey: X25519PublicKey` - Pre-key public key to sign

**Returns:** hex-encoded signature

##### `setIdentityString`

Update the identity string for this X3DH instance.

```ts
setIdentityString(id:string):void
```

**Parameters:**
- `id:string` - New identity string (DID)

## Should I Use This?

Don't use it in production until version 1.0.0 has been tagged.
The API can break at any moment until that happens.

However, feel free to test and play with it.
