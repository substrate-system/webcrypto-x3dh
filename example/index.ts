/**
 * Example: Using X3DH with @substrate-system/keys
 *
 * This example demonstrates how to use the X3DH module with the
 * @substrate-system/keys module for key management and persistence.
 */

import { EccKeys } from '@substrate-system/keys/ecc'
import { webcrypto } from '@substrate-system/one-webcrypto'
import { X3DH, signBundle } from '../src/index.js'

// Helper to convert EccKeys to X3DH format
async function createX3DHKeys (eccKeys) {
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

// Helper to export key as hex
async function keyToHex (key) {
    const raw = await webcrypto.subtle.exportKey('raw', key)
    return Array.from(new Uint8Array(raw))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('')
}

async function example () {
    console.log('X3DH + keys module Example')
    console.log('================================================\n')

    // 1. Create persistent identity keys using @substrate-system/keys
    console.log('1. Creating persistent identity keys...')
    const aliceKeys = await EccKeys.create() // saved to IndexedDB (browser only)
    await aliceKeys.persist()
    const bobKeys = await EccKeys.create()
    await bobKeys.persist()

    console.log(`   Alice DID: ${aliceKeys.DID}`)
    console.log(`   Bob DID: ${bobKeys.DID}\n`)

    // 2. Convert to X3DH format
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

    console.log(`   Alice generated ${aliceBundle.bundle.length} one-time keys`)
    console.log(`   Bob generated ${bobBundle.bundle.length} one-time keys\n`)

    // 5. Simulate server response for key exchange
    console.log('5. Performing X3DH handshake...')
    const bobResponse = async () => {
        const sig = await signBundle(bobX3DHKeys.identitySecret, [bobX3DHKeys.preKeyPublic])
        const identityKeyHex = await keyToHex(bobX3DHKeys.identityPublic)
        const preKeyHex = await keyToHex(bobX3DHKeys.preKeyPublic)
        const sigHex = Array.from(new Uint8Array(sig))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('')

        return {
            IdentityKey: identityKeyHex,
            SignedPreKey: {
                Signature: sigHex,
                PreKey: preKeyHex
            },
            OneTimeKey: bobBundle.bundle[0]
        }
    }

    // 6. Alice initiates communication with Bob
    const initialMessage = 'Hello Bob! This message uses X3DH key agreement.'
    const handshake = await aliceX3DH.initSend(bobKeys.DID, bobResponse, initialMessage)

    console.log('Alice sent initial encrypted message')

    // 7. Bob receives and decrypts
    const [sender, decryptedMessage] = await bobX3DH.initRecv(handshake)

    console.log(`Bob received message from: ${sender}`)
    console.log(`Decrypted: "${decryptedMessage}"\n`)

    // 8. Ongoing secure communication
    console.log('6. Testing ongoing secure communication...')

    // Bob replies
    const bobReply = 'Hello Alice! The X3DH handshake worked perfectly.'
    const encryptedReply = await bobX3DH.encryptNext(aliceKeys.DID, bobReply)
    const aliceReceived = await aliceX3DH.decryptNext(bobKeys.DID, encryptedReply)

    console.log(`   Bob → Alice: "${aliceReceived}"`)

    // Alice responds
    const aliceResponse = 'Great! Our identities are managed by @substrate-system/keys.'
    const encryptedResponse = await aliceX3DH.encryptNext(bobKeys.DID, aliceResponse)
    const bobReceived = await bobX3DH.decryptNext(aliceKeys.DID, encryptedResponse)

    console.log(`   Alice → Bob: "${bobReceived}"\n`)

    // 9. Demonstrate key management features
    console.log('7. Key management features:')
    console.log('   • Identity keys are persisted automatically (browser only)')
    console.log('   • DIDs provide consistent identity across sessions')
    console.log('   • X3DH handles the cryptographic protocol')
    console.log('   • @substrate-system/keys handles key persistence')
    console.log('   • Session keys are managed separately from identity keys\n')

    console.log('Example completed successfully!')
    console.log('\nNOTE: In Node.js environment, use EccKeys.create(true) for' +
        ' session-only keys.')
    console.log('      In browser environment, omit the parameter for ' +
        'automatic persistence.')

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
