import { webcrypto } from '@substrate-system/one-webcrypto'
import { test } from '@substrate-system/tapzero'
import { signBundle, X3DH, type X3DHKeys } from '../src/index.js'
import { toArrayBuffer } from '../src/util.js'

test('generate one time keys', async t => {
    const keys = await generateX3DHKeys()
    const x3dh = new X3DH(keys, 'test-user')
    const response = await x3dh.generateOneTimeKeys(4)
    t.equal(response.bundle.length, 4, '4 bundle length')
    t.equal(response.signature.length, 128, 'should be 128 bits')
})

test('x3dh Handshake with one-time keys', async t => {
    t.plan(9)

    // 1. Generate keys for both users
    const fox_keys = await generateX3DHKeys()
    const wolf_keys = await generateX3DHKeys()

    // 2. Instantiate X3DH objects with keys
    const fox_x3dh = new X3DH(fox_keys, 'fox')
    const wolf_x3dh = new X3DH(wolf_keys, 'wolf')

    t.equal(fox_x3dh.identityString, 'fox')
    t.equal(wolf_x3dh.identityString, 'wolf')

    // 3. Pre-keys are already in the keys objects
    t.ok(fox_keys.preKeyPublic, 'should have fox pre-key')
    t.ok(wolf_keys.preKeyPublic, 'should have wolf pre-key')

    // 4. Generate some one-time keys
    const fox_bundle = await fox_x3dh.generateOneTimeKeys(3)
    t.ok(fox_bundle, 'should generate a fox bundle')
    const wolf_bundle = await wolf_x3dh.generateOneTimeKeys(3)

    // 5. Prepare wolf's public keys
    const sig = await signBundle(wolf_keys.identitySecret, [wolf_keys.preKeyPublic])
    const wolfPkBytes = await exportKeyAsBytes(wolf_keys.identityPublic)
    const preKeyBytes = await exportKeyAsBytes(wolf_keys.preKeyPublic)
    const wolfKeys = {
        IdentityKey: arrayBufferToHex(toArrayBuffer(wolfPkBytes)),
        SignedPreKey: {
            Signature: arrayBufferToHex(toArrayBuffer(sig)),
            PreKey: arrayBufferToHex(toArrayBuffer(preKeyBytes))
        },
        OneTimeKey: wolf_bundle.bundle[0]
    }

    // 6. Do an initial handshake from fox->wolf
    const sendResult = await fox_x3dh.initSend('wolf', wolfKeys)

    // Verify we got a shared secret
    t.ok(sendResult.sharedSecret instanceof Uint8Array,
        'should return shared secret')
    t.equal(sendResult.sharedSecret.length, 32,
        'shared secret should be 32 bytes')

    // 7. Pass the handshake to wolf->fox
    const recvResult = await wolf_x3dh.initReceive(sendResult.handshakeData)
    t.equal(recvResult.senderIdentity, 'fox', 'sender should be "fox"')

    // Verify both sides have the same shared secret
    t.ok(
        arraysEqual(sendResult.sharedSecret, recvResult.sharedSecret),
        'both sides should have the same shared secret'
    )
})

// Helper function to convert bytes to hex string
function arrayBufferToHex (buffer:ArrayBuffer):string {
    return Array.from(new Uint8Array(buffer))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('')
}

// Helper to compare two Uint8Arrays
function arraysEqual (a:Uint8Array, b:Uint8Array):boolean {
    if (a.length !== b.length) return false
    for (let i = 0; i < a.length; i++) {
        if (a[i] !== b[i]) return false
    }
    return true
}

// Helper function to generate Ed25519 key pairs
async function generateEd25519KeyPair ():Promise<{
    publicKey: CryptoKey,
    privateKey: CryptoKey
}> {
    const keyPair = await webcrypto.subtle.generateKey(
        { name: 'Ed25519' },
        true,  // extractable
        ['sign', 'verify']
    ) as CryptoKeyPair
    return { publicKey: keyPair.publicKey, privateKey: keyPair.privateKey }
}

// Helper function to generate X25519 key pairs
async function generateX25519KeyPair ():Promise<{
    publicKey: CryptoKey,
    privateKey: CryptoKey
}> {
    const keyPair = await webcrypto.subtle.generateKey(
        { name: 'X25519' },
        true,  // extractable
        ['deriveKey']
    ) as CryptoKeyPair
    return { publicKey: keyPair.publicKey, privateKey: keyPair.privateKey }
}

// Helper to generate complete X3DH keys
async function generateX3DHKeys (): Promise<X3DHKeys> {
    const identityKeys = await generateEd25519KeyPair()
    const preKeys = await generateX25519KeyPair()

    return {
        identitySecret: identityKeys.privateKey,
        identityPublic: identityKeys.publicKey,
        preKeySecret: preKeys.privateKey,
        preKeyPublic: preKeys.publicKey
    }
}

// Helper function to get raw bytes from a CryptoKey
async function exportKeyAsBytes (key:CryptoKey):Promise<Uint8Array<ArrayBuffer>> {
    const rawKey = await webcrypto.subtle.exportKey('raw', key)
    return new Uint8Array(rawKey)
}
