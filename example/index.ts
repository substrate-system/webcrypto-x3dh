/**
 * Example: Using X3DH with @substrate-system/keys
 *
 * Use with the @substrate-system/keys module.
 */

import { EccKeys } from '@substrate-system/keys/ecc'
import { webcrypto } from '@substrate-system/one-webcrypto'
import Debug from '@substrate-system/debug'
import { toString } from 'uint8arrays'
import { X3DH, signBundle } from '../src/index.js'

window.localStorage.setItem('DEBUG', 'example,example:*')
const debug = Debug('example')

/**
 * Create 2 keypairs -- identity and preKey
 */
async function createX3DHKeys (eccKeys:EccKeys) {
    // Generate X25519 pre-keys (EccKeys uses Ed25519 for identity)
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

async function example () {
    console.log('X3DH + keys Example')
    console.log('================================================\n')

    // 1. Create persistent identity keys using @substrate-system/keys
    console.log('1. Creating persistent identity keys...')
    const aliceKeys = await EccKeys.create()
    await aliceKeys.persist()  // save to IndexedDB
    const bobKeys = await EccKeys.create()
    await bobKeys.persist()

    debug(`   Alice DID: ${aliceKeys.DID}`)
    debug(`   Bob DID: ${bobKeys.DID}\n`)

    // 2. Create X3DH format key packages
    console.log('2. Converting keys to X3DH format...')
    const aliceX3DHKeys = await createX3DHKeys(aliceKeys)
    const bobX3DHKeys = await createX3DHKeys(bobKeys)

    // 3. Create X3DH instances
    console.log('3. Creating X3DH instances...')
    const aliceX3DH = new X3DH(aliceX3DHKeys, aliceKeys.DID)
    const bobX3DH = new X3DH(bobX3DHKeys, bobKeys.DID)

    // 4. Generate one-time key bundles
    console.log('4. Generating one-time key bundles...')
    const aliceBundle = await aliceX3DH.generateOneTimeKeys(5)
    const bobBundle = await bobX3DH.generateOneTimeKeys(5)

    debug(`   Alice generated ${aliceBundle.bundle.length} one-time keys`)
    debug(`   Bob generated ${bobBundle.bundle.length} one-time keys\n`)

    // 5. Simulate server response for key exchange
    console.log('5. Performing X3DH handshake...')
    const sig = await signBundle(
        bobX3DHKeys.identitySecret,
        [bobX3DHKeys.preKeyPublic]
    )
    const identityKeyHex = await keyToHex(bobX3DHKeys.identityPublic)
    const preKeyHex = await keyToHex(bobX3DHKeys.preKeyPublic)
    const sigHex = Array.from(sig)
        .map(b => b.toString(16).padStart(2, '0'))
        .join('')

    const bobPublicKeys = {
        IdentityKey: identityKeyHex,
        SignedPreKey: {
            Signature: sigHex,
            PreKey: preKeyHex
        },
        OneTimeKey: bobBundle.bundle[0]
    }

    // 6. Alice initiates communication with Bob
    const aliceResult = await aliceX3DH.initSend(
        bobKeys.DID,
        bobPublicKeys
    )

    debug('Alice completed X3DH handshake')
    debug("Alice's shared secret: " +
        `${toString(aliceResult.sharedSecret.slice(0, 8), 'hex')}...`)

    // 7. Bob receives and processes the handshake
    const bobResult = await bobX3DH.initReceive(aliceResult.handshakeData)

    debug(`Bob received handshake from: ${bobResult.senderIdentity}`)
    debug("Bob's shared secret: " +
        `${toString(bobResult.sharedSecret.slice(0, 8), 'hex')}...\n`)

    // 8. Verify both parties derived the same secret
    console.log('6. Verifying shared secrets match...')
    const secretsMatch = aliceResult.sharedSecret.every((byte, i) =>
        byte === bobResult.sharedSecret[i]
    )
    console.log(`   Shared secrets match: ${secretsMatch ? '✓' : '✗'}`)

    // 9. What to do next
    console.log('\n7. Next steps:')
    console.log('   • X3DH key exchange is complete')
    console.log('   • Both parties have the same shared secret')
    console.log('   • Use the shared secret to initialize a ratcheting protocol')
    console.log('     (e.g., Double Ratchet) for ongoing message encryption\n')

    console.log('Example completed successfully!')

    // Clean up (browser only)
    if (typeof window !== 'undefined') {
        await aliceKeys.delete()
        await bobKeys.delete()
        console.log('\n🧹 Cleaned up persisted keys')
    }
}

// Run the example
if (typeof window !== 'undefined') {
    example().catch(console.error)
}

export { example }

// Helper
async function keyToHex (key:CryptoKey):Promise<string> {
    const raw = await webcrypto.subtle.exportKey('raw', key)
    return toString(new Uint8Array(raw), 'hex')
}
