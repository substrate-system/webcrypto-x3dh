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
    const bobResponse = async () => {
        const sig = await signBundle(
            bobX3DHKeys.identitySecret,
            [bobX3DHKeys.preKeyPublic]
        )
        const identityKeyHex = await keyToHex(bobX3DHKeys.identityPublic)
        const preKeyHex = await keyToHex(bobX3DHKeys.preKeyPublic)
        const sigHex = Array.from(sig)
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
    const handshake = await aliceX3DH.initSend(
        bobKeys.DID,
        bobResponse,
        initialMessage
    )

    debug('Alice sent initial encrypted message')

    // 7. Bob receives and decrypts
    const [sender, decryptedMessage] = await bobX3DH.initReceive(handshake)

    debug(`Bob received message from: ${sender}`)
    debug(`Decrypted: "${decryptedMessage}"\n`)

    // 8. Ongoing secure communication
    console.log('6. Testing ongoing secure communication...')

    // Bob replies
    const bobReply = 'Hello Alice! The X3DH handshake worked perfectly.'
    const encryptedReply = await bobX3DH.encryptNext(aliceKeys.DID, bobReply)
    const aliceReceived = await aliceX3DH.decryptNext(bobKeys.DID, encryptedReply)

    console.log(`   Bob → Alice: "${aliceReceived}"`)

    // Alice responds
    const aliceResponse = 'Great! Our identities are managed ' +
        'by @substrate-system/keys.'
    const encryptedResponse = await aliceX3DH.encryptNext(bobKeys.DID, aliceResponse)
    const bobReceived = await bobX3DH.decryptNext(aliceKeys.DID, encryptedResponse)

    debug(`   Alice → Bob: "${bobReceived}"\n`)

    // 9. Demonstrate key management features
    console.log('7. Key management features:')
    console.log('   • Identity keys are persisted automatically (browser only)')
    console.log('   • @substrate-system/keys handles key persistence')
    console.log('   • Session keys are managed separately from identity keys\n')

    console.log('Example completed successfully!')
    console.log('\nNOTE: In Node.js environment, use EccKeys.create(true) for' +
        ' session-only keys.')
    console.log('      In browser environment, omit the parameter for ' +
        'persistence.')

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
async function keyToHex (key):Promise<string> {
    const raw = await webcrypto.subtle.exportKey('raw', key)
    return toString(new Uint8Array(raw), 'hex')
}
