import { webcrypto } from '@substrate-system/one-webcrypto'
import { test } from '@substrate-system/tapzero'
import { signBundle, X3DH, type X3DHKeys } from '../src/index.js'
import { toArrayBuffer } from '../src/util.js'

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

test('generate one time keys', async t => {
    const keys = await generateX3DHKeys()
    const x3dh = new X3DH(keys, 'test-user')
    const response = await x3dh.generateOneTimeKeys(4)
    t.equal(response.bundle.length, 4, '4 bundle length')
    t.equal(response.signature.length, 128, 'should be 128 bits')
})

test('x3dh Handshake with one-time keys', async t => {
    t.plan(27)

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

    const wolfResponse = async () => {
        const sig = await signBundle(wolf_keys.identitySecret, [wolf_keys.preKeyPublic])
        const wolfPkBytes = await exportKeyAsBytes(wolf_keys.identityPublic)
        const preKeyBytes = await exportKeyAsBytes(wolf_keys.preKeyPublic)
        return {
            IdentityKey: arrayBufferToHex(toArrayBuffer(wolfPkBytes)),
            SignedPreKey: {
                Signature: arrayBufferToHex(toArrayBuffer(sig)),
                PreKey: arrayBufferToHex(toArrayBuffer(preKeyBytes))
            },
            OneTimeKey: wolf_bundle.bundle[0]
        }
    }

    // 5. Do an initial handshake from fox->wolf
    const message = 'hewwo UwU'
    const sent = await fox_x3dh.initSend('wolf', wolfResponse, message)

    // 6. Pass the handshake to wolf->fox
    const [sender, recv] = await wolf_x3dh.initReceive(sent)
    t.equal(sender, 'fox', 'sender should be "fox"')
    t.equal(recv.toString(), message, 'should decrypt the message')

    // Send and receive a few more:
    for (let i = 0; i < 20; i++) {
        try {
            const plain = `OwO what's this? ${i}`
            if ((i % 3) === 0) {
                const cipher = await wolf_x3dh.encryptNext('fox', plain)
                const decrypt = await fox_x3dh.decryptNext('wolf', cipher)
                t.equal(
                    decrypt.toString(),
                    plain,
                    `round ${i + 1}`
                )
            } else {
                const cipher = await fox_x3dh.encryptNext('wolf', plain)
                const decrypt = await wolf_x3dh.decryptNext('fox', cipher)
                t.equal(
                    decrypt.toString(),
                    plain,
                    `round ${i + 1}`
                )
            }
        } catch (err) {
            console.log('Failed at i = ' + i)
            throw err
        }
    }
})

// Helper function to convert bytes to hex string
function arrayBufferToHex (buffer:ArrayBuffer):string {
    return Array.from(new Uint8Array(buffer))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('')
}
