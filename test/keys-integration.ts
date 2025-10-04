import { test } from '@substrate-system/tapzero'
import { EccKeys } from '@substrate-system/keys/ecc'
import { X3DH, signBundle, type X3DHKeys } from '../src/index.js'
import { webcrypto } from '@substrate-system/one-webcrypto'

// Helper function to convert EccKeys to X3DHKeys format
async function eccKeysToX3DHKeys (eccKeys: EccKeys): Promise<X3DHKeys> {
    // Generate an X25519 key pair for pre-keys since ECC keys are Ed25519
    const preKeyPair = await webcrypto.subtle.generateKey(
        { name: 'X25519' },
        true,
        ['deriveKey']
    ) as CryptoKeyPair

    return {
        identitySecret: eccKeys.privateWriteKey,
        identityPublic: eccKeys.publicWriteKey,
        preKeySecret: preKeyPair.privateKey,
        preKeyPublic: preKeyPair.publicKey
    }
}

// Helper function to get raw bytes from a CryptoKey
async function exportKeyAsBytes (
    key:CryptoKey
):Promise<Uint8Array<ArrayBuffer>> {
    const rawKey = await webcrypto.subtle.exportKey('raw', key)
    return new Uint8Array(rawKey)
}

// Helper function to convert bytes to hex string
function arrayBufferToHex (buffer:ArrayBuffer):string {
    return Array.from(new Uint8Array(buffer))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('')
}

function toArrayBuffer (uint8Array:Uint8Array):ArrayBuffer {
    return uint8Array.buffer.slice(
        uint8Array.byteOffset,
        uint8Array.byteOffset + uint8Array.byteLength
    ) as ArrayBuffer
}

test('X3DH integration with @substrate-system/keys', async t => {
    t.plan(10)

    // 1. Create EccKeys instances for both users (session-only in Node.js
    //   environment)
    const foxKeys = await EccKeys.create(true)  // session-only
    const wolfKeys = await EccKeys.create(true)

    // Verify keys were created
    t.ok(foxKeys.DID, 'Fox should have a DID')
    t.ok(wolfKeys.DID, 'Wolf should have a DID')

    // 2. Convert EccKeys to X3DHKeys format
    const foxX3DHKeys = await eccKeysToX3DHKeys(foxKeys)
    const wolfX3DHKeys = await eccKeysToX3DHKeys(wolfKeys)

    // 3. Create X3DH instances using the keys
    const foxX3DH = new X3DH(foxX3DHKeys, foxKeys.DID)
    const wolfX3DH = new X3DH(wolfX3DHKeys, wolfKeys.DID)

    // 4. Verify identity strings match the DIDs
    t.equal(foxX3DH.identityString, foxKeys.DID,
        'Fox identity should match DID')
    t.equal(wolfX3DH.identityString, wolfKeys.DID,
        'Wolf identity should match DID')

    // 5. Generate one-time key bundles
    const foxBundle = await foxX3DH.generateOneTimeKeys(3)
    const wolfBundle = await wolfX3DH.generateOneTimeKeys(3)

    t.equal(foxBundle.bundle.length, 3, 'Fox should generate 3 one-time keys')
    t.equal(wolfBundle.bundle.length, 3, 'Wolf should generate 3 one-time keys')

    // 6. Create a server response function for Wolf's keys
    const wolfResponse = async () => {
        const sig = await signBundle(
            wolfX3DHKeys.identitySecret,
            [wolfX3DHKeys.preKeyPublic]
        )
        const wolfPkBytes = await exportKeyAsBytes(wolfX3DHKeys.identityPublic)
        const preKeyBytes = await exportKeyAsBytes(wolfX3DHKeys.preKeyPublic)

        return {
            IdentityKey: arrayBufferToHex(toArrayBuffer(wolfPkBytes)),
            SignedPreKey: {
                Signature: arrayBufferToHex(toArrayBuffer(sig)),
                PreKey: arrayBufferToHex(toArrayBuffer(preKeyBytes))
            },
            OneTimeKey: wolfBundle.bundle[0]
        }
    }

    // 7. Perform X3DH handshake from Fox to Wolf
    const message = 'Hello from Fox using keys module!'
    const handshake = await foxX3DH.initSend(wolfKeys.DID, wolfResponse, message)

    // 8. Wolf receives and decrypts the handshake
    const [sender, decryptedMessage] = await wolfX3DH.initReceive(handshake)

    t.equal(sender, foxKeys.DID, 'Sender should be Fox DID')
    t.equal(decryptedMessage.toString(), message,
        'Message should decrypt correctly')

    // 9. Test ongoing message exchange
    const foxMessage = 'Continuing conversation with EccKeys integration'
    const encryptedFromFox = await foxX3DH.encryptNext(wolfKeys.DID, foxMessage)
    const decryptedByWolf = await wolfX3DH.decryptNext(
        foxKeys.DID,
        encryptedFromFox
    )

    t.equal(
        decryptedByWolf.toString(),
        foxMessage,
        'Fox message should decrypt correctly'
    )

    const wolfMessage = 'Reply from Wolf with EccKeys identity'
    const encryptedFromWolf = await wolfX3DH.encryptNext(
        foxKeys.DID,
        wolfMessage
    )
    const decryptedByFox = await foxX3DH.decryptNext(
        wolfKeys.DID,
        encryptedFromWolf
    )

    t.equal(decryptedByFox.toString(), wolfMessage,
        'Wolf message should decrypt correctly')

    // Note: In browser environments, you can use EccKeys.create() without
    //   the session flag to enable persistence via IndexedDB.
    // The keys will automatically be saved and can be reloaded later
    //   with EccKeys.load().
    // Session management (for ongoing conversations)
    //   would need to be handled separately from identity key persistence.
})

test('X3DH with session-only keys (no persistence)', async t => {
    t.plan(5)

    // Create session-only keys (not persisted)
    const aliceKeys = await EccKeys.create(true) // true = session only
    const bobKeys = await EccKeys.create(true)

    // Convert to X3DH format
    const aliceX3DHKeys = await eccKeysToX3DHKeys(aliceKeys)
    const bobX3DHKeys = await eccKeysToX3DHKeys(bobKeys)

    // Create X3DH instances
    const aliceX3DH = new X3DH(aliceX3DHKeys, aliceKeys.DID)
    const bobX3DH = new X3DH(bobX3DHKeys, bobKeys.DID)

    t.ok(aliceX3DH.identityString, 'Alice should have identity string')
    t.ok(bobX3DH.identityString, 'Bob should have identity string')

    // Generate bundles
    const aliceBundle = await aliceX3DH.generateOneTimeKeys(2)
    const bobBundle = await bobX3DH.generateOneTimeKeys(2)

    t.equal(aliceBundle.bundle.length, 2, 'Alice should generate 2 keys')
    t.equal(bobBundle.bundle.length, 2, 'Bob should generate 2 keys')

    // Quick handshake test
    const bobResponse = async () => {
        const sig = await signBundle(
            bobX3DHKeys.identitySecret,
            [bobX3DHKeys.preKeyPublic]
        )
        const bobPkBytes = await exportKeyAsBytes(bobX3DHKeys.identityPublic)
        const preKeyBytes = await exportKeyAsBytes(bobX3DHKeys.preKeyPublic)

        return {
            IdentityKey: arrayBufferToHex(toArrayBuffer(bobPkBytes)),
            SignedPreKey: {
                Signature: arrayBufferToHex(toArrayBuffer(sig)),
                PreKey: arrayBufferToHex(toArrayBuffer(preKeyBytes))
            },
            OneTimeKey: bobBundle.bundle[0]
        }
    }

    const testMessage = 'Session-only message'
    const handshake = await aliceX3DH.initSend(
        bobKeys.DID,
        bobResponse,
        testMessage
    )
    const [_sender, received] = await bobX3DH.initReceive(handshake)

    t.equal(received.toString(), testMessage, 'Session-only keys should work')
})
