import { webcrypto } from '@substrate-system/one-webcrypto'
import { concat } from './util.js'

const VERSION = 'v1'

const PREFIX_ENCRYPTION_KEY = new Uint8Array([
    0x53, 0x6f, 0x61, 0x74, 0x6f, 0x6b, 0x01, 0x01
])
const PREFIX_COMMIT_KEY = new Uint8Array([
    0x53, 0x6f, 0x61, 0x74, 0x6f, 0x6b, 0x01, 0xff
])

/**
 * A wrapper around CryptoKey that uses non-extractable keys for security.
 * Keys are stored as HKDF base keys to enable ratcheting via deriveBits.
 */
export class CryptographyKey {
    private key:CryptoKey

    private constructor (key:CryptoKey) {
        this.key = key
    }

    /**
     * Create a CryptographyKey from raw bytes.
     * The key will be imported as a non-extractable HKDF key.
     */
    static async fromBytes (keyMaterial:Uint8Array):Promise<CryptographyKey> {
        const key = await globalThis.crypto.subtle.importKey(
            'raw',
            keyMaterial,
            'HKDF',
            false, // non-extractable
            ['deriveBits', 'deriveKey']
        )
        return new CryptographyKey(key)
    }

    /**
     * Create a CryptographyKey from an existing CryptoKey.
     */
    static fromCryptoKey (key:CryptoKey):CryptographyKey {
        return new CryptographyKey(key)
    }

    /**
     * Get the underlying CryptoKey object.
     */
    getCryptoKey ():CryptoKey {
        return this.key
    }

    /**
     * Derive bytes from this key using HKDF.
     * Used for encryption key derivation and ratcheting.
     */
    async deriveBits (
        salt:Uint8Array,
        info:Uint8Array,
        length:number
    ):Promise<Uint8Array> {
        const bits = await globalThis.crypto.subtle.deriveBits(
            {
                name: 'HKDF',
                hash: 'SHA-256',
                salt,
                info
            },
            this.key,
            length * 8 // convert bytes to bits
        )
        return new Uint8Array(bits)
    }

    /**
     * Derive a new CryptographyKey from this key using HKDF.
     * Used for key ratcheting.
     */
    async deriveKey (
        salt:Uint8Array,
        info:Uint8Array
    ):Promise<CryptographyKey> {
        // Derive bits and re-import as HKDF key
        const derivedBits = await this.deriveBits(salt, info, 32)
        return await CryptographyKey.fromBytes(derivedBits)
    }

    /**
     * Get raw bytes from this key for intermediate operations like concatenation.
     * Uses deriveBits with empty salt/info to extract the key material.
     * This is needed for X3DH handshake where multiple DH secrets are concatenated.
     */
    async getBytes (length:number = 32):Promise<Uint8Array> {
        return await this.deriveBits(
            new Uint8Array(0), // empty salt
            new Uint8Array(0), // empty info
            length
        )
    }
}

/**
 * Interface for symmetric encryption classes supported by this library.
 */
export interface SymmetricEncryptionInterface {
    encrypt(
        message:string|Uint8Array,
        key:CryptographyKey,
        assocData?:string
    ):Promise<string>;
    decrypt(
        message:string,
        key:CryptographyKey,
        assocData?:string
    ):Promise<string|Uint8Array>;
}

/**
 * Default implementation for SymmetricEncryptionInterface.
 */
export class SymmetricCrypto implements SymmetricEncryptionInterface {
    async encrypt (
        message:string|Uint8Array<ArrayBuffer>,
        key:CryptographyKey,
        assocData?:string
    ):Promise<string> {
        return encryptData(message, key, assocData)
    }

    async decrypt (
        message:string,
        key:CryptographyKey,
        assocData?:string
    ):Promise<string|Uint8Array> {
        return decryptData(message, key, assocData)
    }
}

export type KeyDerivationFunction = (
    ikm:Uint8Array<ArrayBuffer>,
    salt?:Uint8Array<ArrayBuffer>,
    info?:Uint8Array<ArrayBuffer>
) => Promise<Uint8Array<ArrayBuffer>>;

/**
 * Encrypt data using AES-GCM.
 * Provides key commitment.
 *
 * @param {string|Uint8Array} message
 * @param {CryptographyKey} key
 * @param {string|null} assocData
 * @returns {string}
 */
export async function encryptData (
    message:string|Uint8Array<ArrayBuffer>,
    key:CryptographyKey,
    assocData?:string
):Promise<string> {
    const nonce = globalThis.crypto.getRandomValues(new Uint8Array(24))
    const aad = JSON.stringify({
        version: VERSION,
        nonce: arrayBufferToHex(nonce),
        extra: assocData
    })

    const { encKeyBytes, commitment } = await deriveKeys(key, nonce)

    // Convert message to Uint8Array
    const messageBytes = typeof message === 'string' ?
        new TextEncoder().encode(message) :
        message

    // Create AES-GCM key for encryption
    const aesKey = await globalThis.crypto.subtle.importKey(
        'raw',
        encKeyBytes,
        { name: 'AES-GCM' },
        false,
        ['encrypt']
    )

    const iv = globalThis.crypto.getRandomValues(new Uint8Array(12))
    const encrypted = await globalThis.crypto.subtle.encrypt(
        {
            name: 'AES-GCM',
            iv,
            additionalData: new TextEncoder().encode(aad)
        },
        aesKey,
        messageBytes
    )

    return (
        VERSION +
        arrayBufferToHex(nonce) +
        arrayBufferToHex(commitment) +
        arrayBufferToHex(iv) +
        arrayBufferToHex(encrypted)
    )
}

/**
 * Decrypt data using AES-GCM.
 * Asserts key commitment.
 *
 * @param {string} encrypted
 * @param {CryptographyKey} key
 * @param {string|null} assocData
 * @returns {string|Uint8Array}
 */
export async function decryptData (
    encrypted:string,
    key:CryptographyKey,
    assocData?:string
):Promise<string|Uint8Array> {
    const ver = encrypted.slice(0, 2)
    if (ver !== VERSION) {
        throw new Error('Incorrect version: ' + ver)
    }

    const nonce = hexToArrayBuffer(encrypted.slice(2, 50))
    const storedCommitment = hexToArrayBuffer(encrypted.slice(50, 114))
    const iv = hexToArrayBuffer(encrypted.slice(114, 138))
    const ciphertext = hexToArrayBuffer(encrypted.slice(138))

    const aad = JSON.stringify({
        version: ver,
        nonce: encrypted.slice(2, 50),
        extra: assocData
    })

    const { encKeyBytes, commitment } = await deriveKeys(key, new Uint8Array(nonce))

    // Verify commitment
    if (!arrayBuffersEqual(storedCommitment, commitment.buffer)) {
        throw new Error('Incorrect commitment value')
    }

    // Create AES-GCM key for decryption
    const aesKey = await globalThis.crypto.subtle.importKey(
        'raw',
        encKeyBytes,
        { name: 'AES-GCM' },
        false,
        ['decrypt']
    )

    const decrypted = await globalThis.crypto.subtle.decrypt(
        {
            name: 'AES-GCM',
            iv: new Uint8Array(iv),
            additionalData: new TextEncoder().encode(aad)
        },
        aesKey,
        ciphertext
    )

    // Try to decode as UTF-8 text first, fallback to Uint8Array if it fails
    try {
        const text = new TextDecoder('utf-8', { fatal: true }).decode(decrypted)
        return text
    } catch {
        // If UTF-8 decoding fails, return as Uint8Array
        return new Uint8Array(decrypted)
    }
}

/**
 * HKDF implementation using Web Crypto API
 *
 * @param ikm
 * @param salt
 * @param info
 */
export async function blakeKdf (
    ikm:Uint8Array<ArrayBuffer>,
    salt?:Uint8Array<ArrayBuffer>|CryptographyKey,
    info?:Uint8Array<ArrayBuffer>
):Promise<Uint8Array<ArrayBuffer>> {
    if (!salt) {
        salt = new Uint8Array(32) // All zeros
    } else if (salt instanceof CryptographyKey) {
        salt = salt.getBuffer()
    }
    if (!info) {
        info = new TextEncoder().encode('Soatok Dreamseeker test code')
    }

    // Import IKM as HKDF key material
    const keyMaterial = await webcrypto.subtle.importKey(
        'raw',
        ikm,
        'HKDF',
        false,
        ['deriveKey', 'deriveBits']
    )

    // Extract PRK using HKDF-Extract (HMAC with salt)
    const prk = await globalThis.crypto.subtle.deriveBits(
        {
            name: 'HKDF',
            hash: 'SHA-256',
            salt,
            info: new Uint8Array(0) // Empty info for extract phase
        },
        keyMaterial,
        256 // 32 bytes
    )

    // Expand PRK using HKDF-Expand
    const prkKey = await globalThis.crypto.subtle.importKey(
        'raw',
        prk,
        'HKDF',
        false,
        ['deriveBits']
    )

    const expandedKey = await globalThis.crypto.subtle.deriveBits(
        {
            name: 'HKDF',
            hash: 'SHA-256',
            salt: new Uint8Array(0), // Empty salt for expand phase
            info: concat(info, new Uint8Array([0x01]))
        },
        prkKey,
        256 // 32 bytes
    )

    return new Uint8Array(expandedKey)
}

// Helper functions
function arrayBufferToHex (buffer:ArrayBuffer|Uint8Array):string {
    const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer)
    return Array.from(bytes)
        .map(b => b.toString(16).padStart(2, '0'))
        .join('')
}

function hexToArrayBuffer (hex:string):ArrayBuffer {
    const bytes = new Uint8Array(hex.length / 2)
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substr(i, 2), 16)
    }
    return bytes.buffer
}

function arrayBuffersEqual (buf1:ArrayBuffer, buf2:ArrayBuffer):boolean {
    if (buf1.byteLength !== buf2.byteLength) {
        return false
    }
    const view1 = new Uint8Array(buf1)
    const view2 = new Uint8Array(buf2)
    for (let i = 0; i < view1.length; i++) {
        if (view1[i] !== view2[i]) {
            return false
        }
    }
    return true
}

/**
 * Derive an encryption key and a commitment hash using HKDF.
 *
 * @param {CryptographyKey} key
 * @param {Uint8Array} nonce
 * @returns {{encKeyBytes: Uint8Array, commitment: Uint8Array}}
 */
export async function deriveKeys (
    key:CryptographyKey,
    nonce:Uint8Array<ArrayBuffer>
):Promise<{
    encKeyBytes:Uint8Array<ArrayBuffer>;
    commitment:Uint8Array<ArrayBuffer>;
}> {
    // Derive encryption key using HKDF
    const encKeyBytes = await key.deriveBits(
        nonce,
        PREFIX_ENCRYPTION_KEY,
        32
    )

    // Derive commitment using HKDF
    const commitment = await key.deriveBits(
        nonce,
        PREFIX_COMMIT_KEY,
        32
    )

    return { encKeyBytes, commitment }
}
