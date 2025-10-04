/**
 * X3DH -- eXtended 3-way Diffie-Hellman
 *
 * Specification by Open Whisper Systems <https://signal.org/docs/specifications/x3dh/>
 */
import { webcrypto } from '@substrate-system/one-webcrypto'
import {
    CryptographyKey,
    type KeyDerivationFunction,
    blakeKdf
} from './symmetric.js'
import {
    concat,
    generateKeyPair,
    generateBundle,
    signBundle,
    verifyBundle,
    wipe,
    arrayBufferToHex,
    hexToArrayBuffer
} from './util.js'

// Type aliases for keys module equivalents
export type Ed25519SecretKey = CryptoKey
export type Ed25519PublicKey = CryptoKey
export type X25519SecretKey = CryptoKey
export type X25519PublicKey = CryptoKey

// Helper functions for key import/export
async function importEd25519PublicKey (
    hexString:string
):Promise<Ed25519PublicKey> {
    const keyBytes = hexToArrayBuffer(hexString)

    // Validate Ed25519 public key size
    if (keyBytes.byteLength !== 32) {
        throw new Error(`Invalid Ed25519 public key size: expected 32 bytes, got ${keyBytes.byteLength} bytes. Hex: ${hexString}`)
    }

    try {
        // Try to import as Ed25519 key (structured format)
        return await webcrypto.subtle.importKey(
            'raw',
            keyBytes,
            { name: 'Ed25519' },
            true,
            ['verify']
        )
    } catch (e:unknown) {
        throw new Error(`Failed to import Ed25519 public key: ${e instanceof Error ? e.message : String(e)}`)
    }
}

async function importX25519PublicKey (hexString:string):Promise<X25519PublicKey> {
    const keyBytes = hexToArrayBuffer(hexString)

    try {
        return await webcrypto.subtle.importKey(
            'raw',
            keyBytes,
            { name: 'X25519' },
            true,
            []
        )
    } catch (e:unknown) {
        throw new Error(`Failed to import X25519 public key: ${e instanceof Error ? e.message : String(e)}`)
    }
}

// X25519 scalar multiplication using Web Crypto API (minimal for ECDH)
async function scalarMult (
    privateKey:X25519SecretKey,
    publicKey:X25519PublicKey
):Promise<CryptographyKey> {
    // Use the Web Crypto API's X25519 ECDH for proper key derivation
    const derivedKey = await webcrypto.subtle.deriveKey(
        { name: 'X25519', public: publicKey },
        privateKey,
        { name: 'AES-GCM', length: 256 },
        true, // extractable
        ['encrypt', 'decrypt']
    )

    // Export the key to get the raw shared secret
    const sharedSecret = await webcrypto.subtle.exportKey('raw', derivedKey)
    return await CryptographyKey.fromBytes(new Uint8Array(sharedSecret))
}

/**
 * Type returned from the server when initiating a connection.
 */
export type InitServerInfo = {
    IdentityKey:string;
    SignedPreKey:{
        Signature:string;
        PreKey:string;
    };
    OneTimeKey?:string;
};

// No need for Ed25519 to X25519 conversion
// Ed25519: Identity and signing
// X25519: ECDH operations

type InitClientFunction = (id:string)=>Promise<InitServerInfo>

/**
 * Type sent from the sender to the recipient when initiating a connection.
 */
export type InitSenderInfo = {
    Sender:string,
    IdentityKey:string,
    PreKey:string,
    EphemeralKey:string,
    OneTimeKey?:string,
}

/**
 * Signed bundle of one-time keys.
 */
export type SignedBundle = {
    signature:string,
    bundle:string[]
}

/**
 * X3DH key bundle.
 */
export type X3DHKeys = {
    identitySecret:Ed25519SecretKey
    identityPublic:Ed25519PublicKey
    preKeySecret:X25519SecretKey
    preKeyPublic:X25519PublicKey
}

/**
 * Result from initSend - includes shared secret
 */
export type InitSendResult = {
    sharedSecret: Uint8Array
    handshakeData: InitSenderInfo
}

/**
 * Result from initReceive - includes shared secret and sender identity
 */
export type InitReceiveResult = {
    sharedSecret: Uint8Array
    senderIdentity: string
}

/**
 * X3DH implementation using Web Crypto API.
 * Keys are passed in instead of being managed internally.
 */
export class X3DH {
    kdf:KeyDerivationFunction
    keys:X3DHKeys
    identityString:string
    oneTimeKeys:Map<string, CryptoKey>

    static async prekeys ():Promise<CryptoKeyPair> {
        const preKeyPair = await webcrypto.subtle.generateKey(
            { name: 'X25519' },
            true,
            ['deriveKey']
        )

        return preKeyPair as CryptoKeyPair
    }

    static X3DHKeys (
        idKeys:{
            privateWriteKey:Ed25519SecretKey,
            publicWriteKey:Ed25519PublicKey
        },
        preKeypair:{
            privateKey:X25519SecretKey,
            publicKey:X25519PublicKey
        }
    ):X3DHKeys {
        return {
            identitySecret: idKeys.privateWriteKey,
            identityPublic: idKeys.publicWriteKey,
            preKeySecret: preKeypair.privateKey,
            preKeyPublic: preKeypair.publicKey
        }
    }

    constructor (
        keys:X3DHKeys,
        identityString:string,
        kdf?:KeyDerivationFunction
    ) {
        if (!kdf) {
            kdf = blakeKdf
        }
        this.kdf = kdf
        this.keys = keys
        this.identityString = identityString
        this.oneTimeKeys = new Map<string, CryptoKey>()
    }

    /**
     * Generates and signs a bundle of one-time keys.
     * Stores them locally for later use.
     *
     * @param {number} [numKeys=100]
     * @returns {Promise<SignedBundle>}
     */
    async generateOneTimeKeys (numKeys:number = 100):Promise<SignedBundle> {
        try {
            const bundle = await generateBundle(numKeys)
            const publicKeys = bundle.map(x => x.publicKey)
            const signature = await signBundle(this.keys.identitySecret, publicKeys)

            for (const kp of bundle) {
                // Export X25519 public key as raw bytes
                const pkBytes = await webcrypto.subtle.exportKey('raw', kp.publicKey)
                const pkHex = arrayBufferToHex(pkBytes)
                this.oneTimeKeys.set(pkHex, kp.secretKey)
            }

            const publicKeysHex = await Promise.all(
                publicKeys.map(async pk => {
                    const bytes = await webcrypto.subtle.exportKey('raw', pk)
                    return arrayBufferToHex(bytes)
                })
            )

            return {
                signature: arrayBufferToHex(signature),
                bundle: publicKeysHex
            }
        } catch (err) {
            throw new Error('Failed to generate one-time keys: ' + err)
        }
    }

    private async fetchAndWipeOneTimeSecretKey (pubKey:string):Promise<X25519SecretKey> {
        const found = this.oneTimeKeys.get(pubKey)
        if (!found) {
            throw new Error('Public key not found locally: ' + pubKey)
        }
        this.oneTimeKeys.delete(pubKey)
        return found
    }

    /**
     * Initiate X3DH key exchange as the sender.
     * Returns the shared secret and handshake data to send to recipient.
     *
     * @param {string} recipientIdentity
     * @param {InitClientFunction} getServerResponse
     */
    async initSend (
        recipientIdentity:string,
        getServerResponse:InitClientFunction
    ):Promise<InitSendResult> {
        const senderIdentity = this.identityString
        const senderPreKey = this.keys

        const res:InitServerInfo = await getServerResponse(recipientIdentity)

        // Verify the signature on the signed pre-key
        const identityKey = await importEd25519PublicKey(res.IdentityKey)
        const signedPreKey = await importX25519PublicKey(res.SignedPreKey.PreKey)
        const signatureHex = hexToArrayBuffer(res.SignedPreKey.Signature)

        const validSignature = await verifyBundle(
            identityKey,
            [signedPreKey],
            new Uint8Array(signatureHex)
        )

        if (!validSignature) {
            throw new Error(
                'Invalid signature on signed pre-key for ' + recipientIdentity
            )
        }

        // Generate ephemeral key pair
        const ephPair = await generateKeyPair()
        const ephSecret:X25519SecretKey = ephPair.secretKey
        const ephPublic:X25519PublicKey = ephPair.publicKey

        // See the X3DH specification
        // DH1 = DH(IK_A, SPK_B) - sender identity (pre-key)
        //   with recipient's signed pre-key
        // DH2 = DH(EK_A, IK_B) - sender ephemeral with recipient's
        //   identity (signed pre-key)
        // DH3 = DH(EK_A, SPK_B) - sender ephemeral with recipient's
        //   signed pre-key

        const DH1 = await scalarMult(senderPreKey.preKeySecret, signedPreKey)
        // Use signed pre-key as recipient identity
        const DH2 = await scalarMult(ephSecret, signedPreKey)
        const DH3 = await scalarMult(ephSecret, signedPreKey)
        let SK:Uint8Array
        if (res.OneTimeKey) {
            const otk = await importX25519PublicKey(res.OneTimeKey)
            const DH4 = await scalarMult(ephSecret, otk)
            SK = new Uint8Array(await this.kdf(
                concat(
                    await DH1.getBytes(),
                    await DH2.getBytes(),
                    await DH3.getBytes(),
                    await DH4.getBytes()
                )
            ))
            await wipe(DH4)
        } else {
            SK = new Uint8Array(await this.kdf(
                concat(
                    await DH1.getBytes(),
                    await DH2.getBytes(),
                    await DH3.getBytes()
                )
            ))
        }

        // Wipe DH keys since we have SK
        await wipe(DH1)
        await wipe(DH2)
        await wipe(DH3)

        const handshakeData: InitSenderInfo = {
            Sender: senderIdentity,
            IdentityKey: arrayBufferToHex(
                await webcrypto.subtle.exportKey('raw', senderPreKey.identityPublic)
            ),
            PreKey: arrayBufferToHex(
                await webcrypto.subtle.exportKey('raw', senderPreKey.preKeyPublic)
            ),
            EphemeralKey: arrayBufferToHex(
                await webcrypto.subtle.exportKey('raw', ephPublic)
            ),
            OneTimeKey: res.OneTimeKey
        }

        return {
            sharedSecret: SK,
            handshakeData
        }
    }

    /**
     * Receive and process an initial X3DH handshake message.
     * Returns the shared secret and sender's identity.
     *
     * @param {InitSenderInfo} req
     * @returns {Promise<InitReceiveResult>}
     */
    async initReceive (req:InitSenderInfo):Promise<InitReceiveResult> {
        const preKeySecret = this.keys.preKeySecret
        const recipientPreKey = this.keys

        // Validate sender's identity key signature
        const senderPreKey = await importX25519PublicKey(req.PreKey)
        const ephemeral = await importX25519PublicKey(req.EphemeralKey)

        // Perform X3DH
        const DH1 = await scalarMult(preKeySecret, senderPreKey)
        const DH2 = await scalarMult(recipientPreKey.preKeySecret, ephemeral)
        const DH3 = await scalarMult(preKeySecret, ephemeral)

        let SK:Uint8Array
        if (req.OneTimeKey) {
            const otk = await this.fetchAndWipeOneTimeSecretKey(req.OneTimeKey)
            const DH4 = await scalarMult(otk, ephemeral)
            SK = new Uint8Array(await this.kdf(
                concat(
                    await DH1.getBytes(),
                    await DH2.getBytes(),
                    await DH3.getBytes(),
                    await DH4.getBytes()
                )
            ))
            await wipe(DH4)
        } else {
            SK = new Uint8Array(await this.kdf(
                concat(
                    await DH1.getBytes(),
                    await DH2.getBytes(),
                    await DH3.getBytes()
                )
            ))
        }
        // Wipe DH keys since we have SK
        await wipe(DH1)
        await wipe(DH2)
        await wipe(DH3)

        return {
            sharedSecret: SK,
            senderIdentity: req.Sender
        }
    }

    /**
     * Sign a pre-key with the identity key.
     * This is what should be used for signed pre-keys in X3DH.
     *
     * @param {Ed25519SecretKey} signingKey
     * @param {X25519PublicKey} preKey
     */
    async signPreKey (
        signingKey:Ed25519SecretKey,
        preKey:X25519PublicKey
    ):Promise<string> {
        const signature = await signBundle(signingKey, [preKey])
        return arrayBufferToHex(signature)
    }

    /**
     * Sets the identity string for the current user.
     *
     * @param {string} id
     */
    setIdentityString (id: string): void {
        this.identityString = id
    }
}

// export the interfaces we use
export * from './symmetric'
export * from './util'
