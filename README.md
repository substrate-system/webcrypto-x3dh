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
so is usable in browsers.

## fork

This is a fork of [soatok/rawr-x3dh](https://github.com/soatok/rawr-x3dh).
Thanks `@soatok` for working in public.

## Contents

<!-- toc -->

- [What's This?](#whats-this)
- [Platform Independence](#platform-independence)
  * [Improved Browser Compatibility (v0.4.0)](#improved-browser-compatibility-v040)
  * [Key Storage](#key-storage)
- [Installation](#installation)
- [Usage](#usage)
- [Should I Use This?](#should-i-use-this)

<!-- tocstop -->

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
- Automatically detects and supports both raw (32-byte) and structured
  (SPKI/PKCS8) Ed25519 key formats
- Exports keys in the format most compatible with the current environment
- Fallback mechanisms ensure keys work across different Web Crypto
  API implementations


### Key Management

This library integrates with `@substrate-system/keys` for identity
key management:

- **Identity Keys**: Long-term Ed25519/X25519 keys managed
  by `@substrate-system/keys`
- **Session Keys**: Short-term keys for ongoing conversations stored
  in IndexedDB
- **Automatic Storage**: Identity keys persist to IndexedDB in browsers,
  session-only in Node.js
- **Environment Detection**: Automatically uses IndexedDB when available,
  falls back to memory

## Usage

### Basics with `@substrate-system/keys`

```ts
import { EccKeys } from '@substrate-system/keys/ecc'
import { webcrypto } from '@substrate-system/one-webcrypto'
import { X3DH } from '@substrate-system/webcrypto-x3dh'

// 1. Create identity keys with @substrate-system/keys
const aliceKeys = await EccKeys.create()
await aliceKeys.persist()

// 2. Generate X25519 pre-keys for X3DH
const preKeyPair = await X3DH.prekeys()

// 3. Create X3DH keys object
const x3dhKeys = X3DH.X3DHKeys(aliceKeys, preKeyPair)

// 4. Initialize X3DH with keys and identity string
const x3dh = new X3DH(x3dhKeys, aliceKeys.DID)
```

### Constructor Options

You can customize the X3DH implementation:

```ts
const x3dh = new X3DH(
  x3dhKeys,                    // X3DHKeys (required)
  identityString,              // string/DID (required)
  sessionKeyManager,           // SessionKeyManagerInterface (optional)
  symmetricEncryptionHandler,  // SymmetricEncryptionInterface (optional)
  keyDerivationFunction        // KeyDerivationFunction (optional)
)
```

Session keys are automatically persisted using IndexedDB in browsers.


### Performing X3DH Key Exchange

Once your X3DH object has been created, you can perform key exchanges and
encrypt messages:

```ts
// Generate one-time keys for others to use
const oneTimeKeyBundle = await x3dh.generateOneTimeKeys(10)
// Upload oneTimeKeyBundle to your server so others can retrieve them
// during key exchange

// Initiate communication (sender side)
const firstEncrypted = await x3dh.initSend(
    'recipient-did-string',
    serverApiCallFunc,
    firstMessage
)
```

The `serverApiCallFunc` parameter should be a function that sends a request to
the server to obtain the identity key, signed pre-key, and optional one-time
key for the handshake.

See the definition of the `InitClientFunction` type in
[src/index.ts](https://github.com/substrate-system/webcrypto-x3dh/blob/e0a3a1a342317de116ee41f73072448a8218da5c/src/index.ts#L134).

```ts
type InitClientFunction = (id:string)=>Promise<InitServerInfo>

type InitServerInfo = {
    IdentityKey:string;
    SignedPreKey:{
        Signature:string;
        PreKey:string;
    };
    OneTimeKey?:string;
};
```


### Receiving and Ongoing Communication

```ts
// Receive initial message (recipient side)
const [senderDID, firstMessage] = await x3dh.initReceive(handshakeData)

// Ongoing secure communication
const nextEncrypted = await x3dh.encryptNext('recipient-did', 'Follow-up message')
const nextMessage = await x3dh.decryptNext('sender-did', nextEncrypted)
```

Note: `initReceive()` returns the sender's DID and the decrypted message.
Session keys are automatically managed and ratcheted for forward secrecy.

### Session Key Management

Session keys are automatically managed with the following features:

- **IndexedDB Storage**: In browsers, session keys persist across page reloads
- **Memory Fallback**: In Node.js or environments without IndexedDB, uses
  memory storage
- **Forward Secrecy**: Keys are ratcheted after each message using SHA-256
- **Automatic Cleanup**: Use `destroySessionKey(participantId)` to clean
  up sessions

```ts
// Clean up a session when conversation ends
await x3dh.sessionKeyManager.destroySessionKey('participant-did')

// List all active sessions
const sessions = await x3dh.sessionKeyManager.listSessionIds()
```

However, that doesn't mean it's trustworthy! This library only implements
the X3DH pattern. It doesn't implement the
[Gossamer integration](https://soatok.blog/2020/11/14/going-bark-a-furrys-guide-to-end-to-end-encryption/#identity-key-management).

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
    OneTimeKey?: string,
    CipherText: string
}
```

### Main Classes

- `X3DH` - Main class for X3DH operations
- `IndexedDBSessionManager` - Session key storage using IndexedDB
- `MemorySessionManager` - In-memory session key storage
- `SymmetricCrypto` - Default symmetric encryption implementation

## Should I Use This?

Don't use it in production until version 1.0.0 has been tagged.
The API can break at any moment until that happens (especially if
I decide I hate the default key management classes I wrote).

However, feel free to test and play with it.
