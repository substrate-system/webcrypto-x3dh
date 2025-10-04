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

X3DH (Extended Triple Diffie-Hellman) is a secure key exchange protocol for
end-to-end encrypted communication.
It allows two parties to establish a shared secret for encrypted messaging,
even when one party is offline. This library implements X3DH for browsers
using the Web Crypto API, enabling secure initial handshakes. It also includes
a basic symmetric ratcheting mechanism for ongoing message encryption (not the
Double Ratchet protocol used by Signal).

In browser environments, this library automatically stores derived
session keys in `IndexedDB` (database: `x3dh-sessions`) so ongoing conversations
persist across page reloads. Only the symmetric encryption keys derived from
the X3DH handshake are stored - your identity keys should be managed separately,
e.g. by `@substrate-system/keys`. One-time keys are kept in memory only and
not persisted.

## fork

This is a fork of [soatok/rawr-x3dh](https://github.com/soatok/rawr-x3dh).
Thanks `@soatok` for working in public.

## Contents

<!-- toc -->

- [Install](#install)
- [What's This?](#whats-this)
- [Platform Independence](#platform-independence)
  * [Improved Browser Compatibility (v0.4.0)](#improved-browser-compatibility-v040)
  * [Key Management](#key-management)
- [Usage](#usage)
  * [Basics with `@substrate-system/keys`](#basics-with-substrate-systemkeys)
  * [Constructor Options](#constructor-options)
  * [Performing X3DH Key Exchange](#performing-x3dh-key-exchange)
  * [Receiving and Ongoing Communication](#receiving-and-ongoing-communication)
  * [Session Key Management](#session-key-management)
- [API Reference](#api-reference)
  * [Types](#types)
  * [Main Classes](#main-classes)
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

- **Identity Keys**: Long-term Ed25519/X25519 keys managed by
  `@substrate-system/keys` (persisted separately by that library)
- **Session Keys**: Derived symmetric keys for ongoing conversations,
  stored in IndexedDB under database name `x3dh-sessions` with two object stores:
  - `sessions`: Stores ratcheting symmetric encryption keys (sending and
    receiving) keyed by participant DID
  - `assocData`: Stores associated data strings for AEAD encryption,
    keyed by participant DID
- **Environment Detection**: Automatically uses IndexedDB when available,
  falls back to in-memory storage (not persisted)

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

// 5. Generate one-time keys for others to use in key exchange
const oneTimeKeyBundle = await x3dh.generateOneTimeKeys(10)
// Upload oneTimeKeyBundle to your server
```

### Constructor Options

Can pass in everything:

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
const firstEncryptedMsg = await x3dh.initSend(
    'recipient-did-string',
    serverApiCall,
    firstMessage
)
```

The `serverApiCall` parameter should be a function that sends a request to
the server to obtain the identity key, signed pre-key, and optional one-time
key for the handshake.

See the definition of the `InitClientFunction` type in
[src/index.ts](./src/index.ts#L130).

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
Session keys are automatically managed and ratcheted using a simple symmetric
ratchet (SHA-256 hash of the previous key). **This is not the Double Ratchet
protocol** - for production messaging similar to Signal, you would need to
implement Double Ratchet separately after the X3DH handshake.

### Session Key Management

Session keys are automatically managed with the following features:

- **IndexedDB Storage**: In browsers, derived symmetric session keys
  (sending/receiving pairs) persist across page reloads in the `x3dh-sessions`
  database. **Note**: One-time keys generated with `generateOneTimeKeys()` are
  stored in memory only, not persisted to IndexedDB
- **Memory Fallback**: In Node.js, or environments without IndexedDB, uses
  in-memory storage (all keys lost when process ends)
- **Basic Ratcheting**: Session keys are ratcheted after each message using
  SHA-256 (simple symmetric ratchet, not Double Ratchet)
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
- [`IndexedDBSessionManager`](#indexeddbsessionmanager) - Session key storage
  using IndexedDB
- [`MemorySessionManager`](#memorysessionmanager) - In-memory session
  key storage
- [`SymmetricCrypto`](#symmetriccrypto) - Default symmetric
  encryption implementation

#### X3DH

Main class for performing X3DH key exchanges and managing
encrypted communication.

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
  sessionKeyManager?:SessionKeyManagerInterface,
  encryptor?:SymmetricEncryptionInterface,
  kdf?:KeyDerivationFunction
)
```

Creates a new X3DH instance.

**Parameters:**
- `keys: X3DHKeys` (required) - Identity and pre-keys for this participant
- `identityString: string` (required) - Unique identifier (typically a DID)
  for this participant
- `sessionKeyManager?: SessionKeyManagerInterface` (optional) - Custom
  session storage (defaults to auto-detected IndexedDB or memory storage)
- `encryptor?: SymmetricEncryptionInterface` (optional) - Custom encryption
  mplementation (defaults to `SymmetricCrypto`)
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

Initiates a new encrypted conversation with a recipient. Performs X3DH
handshake and encrypts the first message.

```ts
initSend(
  recipientIdentity:string,
  getServerResponse:(id: string) => Promise<{
    IdentityKey:string
    SignedPreKey:{
      Signature:string
      PreKey:string
    }
    OneTimeKey?:string
  }>,
  message:string|Uint8Array
):Promise<{
  Sender:string
  IdentityKey:string
  PreKey:string
  EphemeralKey:string
  OneTimeKey?:string
  CipherText:string
}>
```

Initiates a new encrypted conversation with a recipient. Performs X3DH
handshake and encrypts the first message.

**Parameters:**
- `recipientIdentity:string` - DID or identifier of the recipient
- `getServerResponse:InitClientFunction` - Async function that fetches
  recipient's public keys from server
- `message:string|Uint8Array` - First message to encrypt and send

**Returns:** Promise resolving to `InitSenderInfo` containing handshake data
and encrypted message to send to recipient

**Side effects:** Stores session keys in `sessionKeyManager`
(IndexedDB if available)

**Example:**
```ts
const handshake = await x3dh.initSend(
  'did:example:bob',
  async (id) => await fetch(`/api/keys/${id}`).then(r => r.json()),
  'Hello Bob!'
)

// Now send the handshake to recipient
```

##### `initReceive`

Receive and process an initial handshake message from a sender. Establishes
session keys and decrypts the first message.

```ts
initReceive(req:{
  sender:string
  identityKey:string
  preKey:string
  ephemeralKey:string
  oneTimeKey?:string
  cipherText:string
}):Promise<[string, string|Uint8Array]>
```

**Parameters:**
- `req:InitSenderInfo` - Handshake data received from sender

**Returns:** Promise resolving to array `[senderDID, decryptedMessage]`

**Side effects:** Stores session keys in `sessionKeyManager`
(IndexedDB if available)

**Throws:** Error if signature verification fails or decryption fails
(and cleans up session)

**Example:**
```ts
const [senderDID, firstMessage] = await x3dh.initReceive(handshakeData)
console.log(`Received from ${senderDID}: ${firstMessage}`)
```

##### `encryptNext`

Encrypt a message in an ongoing conversation. Use existing session keys, and
ratchet forward.

```ts
encryptNext(recipient:string, message:string|Uint8Array):Promise<string>
```

**Parameters:**
- `recipient:string` - DID or identifier of the message recipient
- `message:string|Uint8Array` - Message to encrypt

**Returns:** Promise resolving to hex-encoded encrypted message

**Side effects:** Updates ratcheted session keys in IndexedDB (if available)

**Example:**
```ts
const encrypted = await x3dh.encryptNext('did:example:bob', 'Follow-up message')
// Send encrypted to recipient
```

##### `decryptNext`

Decrypt a message in an ongoing conversation. Use and ratchet existing
session keys.

```ts
decryptNext(sender:string, encrypted:string):Promise<string|Uint8Array>
```

**Parameters:**
- `sender:string` - DID or identifier of the message sender
- `encrypted:string` - Encrypted message to decrypt

**Returns:** Promise resolving to decrypted message (string or Uint8Array)

**Side effects:** Updates ratcheted session keys in IndexedDB (if available)

**Example:**
```ts
const message = await x3dh.decryptNext('did:example:alice', encryptedData)
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

#### IndexedDBSessionManager

Session key manager that persists derived symmetric session keys to IndexedDB
for cross-session persistence in browsers. Stores data in database `x3dh-sessions`:
- Object store `sessions`: Serialized sending/receiving key pairs (as number arrays)
- Object store `assocData`: Associated data strings for AEAD encryption

**Methods:**

##### `setSessionKey`

```ts
setSessionKey(id:string, key:CryptographyKey, recipient?:boolean):Promise<void>
```

Stores session keys for a conversation participant. Derives separate sending and receiving keys from the shared secret.

**Parameters:**
- `id: string` - Participant identifier (DID)
- `key: CryptographyKey` - Shared secret from X3DH handshake
- `recipient?: boolean` - If true, we are receiving; if false, we are sending

**Side effects:** Stores keys to IndexedDB under database `x3dh-sessions`

##### `getEncryptionKey`

```ts
getEncryptionKey(id:string, recipient?:boolean):Promise<CryptographyKey>
```

Retrieves and ratchets the encryption key for the next message. Implements a simple symmetric ratchet (SHA-256 hash).

**Parameters:**
- `id: string` - Participant identifier
- `recipient?: boolean` - If true, ratchet receiving key; if false, ratchet sending key

**Returns:** Promise resolving to encryption key for this message

**Side effects:** Reads current session keys from IndexedDB, then updates with ratcheted keys

**Throws:** Error if session not found

##### `getAssocData`

```ts
getAssocData(id:string):Promise<string>
```

Retrieves associated data for a session (used in AEAD encryption).

**Parameters:**
- `id: string` - Participant identifier

**Returns:** Promise resolving to associated data string (or empty string if not found)

**Side effects:** Reads from IndexedDB

##### `setAssocData`

```ts
setAssocData(id:string, assocData:string):Promise<void>
```

Stores associated data for a session.

**Parameters:**
- `id: string` - Participant identifier
- `assocData: string` - Associated data to store

**Side effects:** Stores associated data to IndexedDB under database `x3dh-sessions`

##### `listSessionIds`

```ts
listSessionIds(): Promise<string[]>
```

Lists all active session IDs.

**Returns:** Promise resolving to array of participant identifiers

**Side effects:** Reads from IndexedDB

##### `destroySessionKey`

```ts
destroySessionKey(id:string):Promise<void>
```

Securely wipes and removes session keys for a participant.

**Parameters:**
- `id: string` - Participant identifier

**Side effects:** Removes keys from IndexedDB and wipes from memory


---


#### MemorySessionManager

In-memory session key manager used as fallback when IndexedDB is unavailable
(e.g., Node.js). Implements the same interface as `IndexedDBSessionManager`
but stores keys in memory only.

**Methods:**

Same methods as `IndexedDBSessionManager`, but stores all data in-memory using
`Map` objects. Session data is lost when the process ends or object is
garbage collected.

#### SymmetricCrypto

Default symmetric encryption implementation using AES-GCM with key commitment.

**Methods:**

##### `encrypt`

```ts
encrypt(
  message:string|Uint8Array,
  key:CryptographyKey,
  assocData?:string
):Promise<string>
```

Encrypt a message using AES-GCM with associated data and key commitment.

**Parameters:**
- `message:string|Uint8Array` - Plaintext to encrypt
- `key:CryptographyKey` - Encryption key
- `assocData?:string` - Optional associated data for AEAD

**Returns:** Promise resolving to hex-encoded encrypted string
(format: version + nonce + commitment + iv + ciphertext)

##### `decrypt`

Decrypt an AES-GCM encrypted message and verify key commitment.

```ts
decrypt(
  message:string,
  key:CryptographyKey,
  assocData?:string
):Promise<string|Uint8Array>
```

**Parameters:**
- `message: string` - Hex-encoded encrypted message
- `key: CryptographyKey` - Decryption key
- `assocData?: string` - Optional associated data for AEAD

**Returns:** Promise resolving to decrypted message (string if valid UTF-8,
Uint8Array otherwise)

**Throws:** Error if version incorrect, commitment verification fails,
or decryption fails

## Should I Use This?

Don't use it in production until version 1.0.0 has been tagged.
The API can break at any moment until that happens (especially if
I decide I hate the default key management classes I wrote).

However, feel free to test and play with it.
