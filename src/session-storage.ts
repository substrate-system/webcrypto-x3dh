import {
    wipe,
    arrayBufferToHex
} from './util.js'
import { CryptographyKey } from './symmetric.js'

type SessionKeys = {
    sending:CryptographyKey,
    receiving:CryptographyKey
}

type SerializedSessionKeys = {
    sending:number[],
    receiving:number[]
}

/**
 * IndexedDB-based session key manager for key ratcheting scenarios.
 * Stores evolving session keys for ongoing conversations.
 */
export class IndexedDBSessionManager {
    private dbName = 'x3dh-sessions'
    private dbVersion = 1
    private sessionStore = 'sessions'
    private assocDataStore = 'assocData'
    private db:IDBDatabase|null = null

    private async openDB ():Promise<IDBDatabase> {
        if (this.db) return this.db

        return new Promise((resolve, reject) => {
            if (typeof indexedDB === 'undefined') {
                // Fallback for environments without IndexedDB
                reject(new Error('IndexedDB not available'))
                return
            }

            const request = indexedDB.open(this.dbName, this.dbVersion)

            request.onerror = () => reject(request.error)
            request.onsuccess = () => {
                this.db = request.result
                resolve(this.db)
            }

            request.onupgradeneeded = (event) => {
                const db = (event.target as IDBOpenDBRequest).result

                if (!db.objectStoreNames.contains(this.sessionStore)) {
                    db.createObjectStore(this.sessionStore)
                }

                if (!db.objectStoreNames.contains(this.assocDataStore)) {
                    db.createObjectStore(this.assocDataStore)
                }
            }
        })
    }

    async getAssocData (id:string):Promise<string> {
        try {
            const db = await this.openDB()
            const tx = db.transaction([this.assocDataStore], 'readonly')
            const store = tx.objectStore(this.assocDataStore)

            return new Promise((resolve, reject) => {
                const request = store.get(id)
                request.onerror = () => reject(request.error)
                request.onsuccess = () => resolve(request.result || '')
            })
        } catch {
            return ''
        }
    }

    async setAssocData (id:string, assocData:string):Promise<void> {
        try {
            const db = await this.openDB()
            const tx = db.transaction([this.assocDataStore], 'readwrite')
            const store = tx.objectStore(this.assocDataStore)

            return new Promise((resolve, reject) => {
                const request = store.put(assocData, id)
                request.onerror = () => reject(request.error)
                request.onsuccess = () => resolve()
            })
        } catch {
            // Fail silently for environments without IndexedDB
        }
    }

    async listSessionIds ():Promise<string[]> {
        try {
            const db = await this.openDB()
            const tx = db.transaction([this.sessionStore], 'readonly')
            const store = tx.objectStore(this.sessionStore)

            return new Promise((resolve, reject) => {
                const request = store.getAllKeys()
                request.onerror = () => reject(request.error)
                request.onsuccess = () => resolve(request.result as string[])
            })
        } catch {
            return []
        }
    }

    /**
     * Store session keys for a participant.
     * Creates domain-separated sending/receiving keys from the shared secret.
     */
    async setSessionKey (
        id:string,
        key:CryptographyKey,
        recipient?:boolean
    ):Promise<void> {
        try {
            const sessionKeys:SessionKeys = {} as SessionKeys
            const keyBuffer = key.getBuffer()

            if (recipient) {
                // We are the recipient: they send to us, we receive from them
                const sendingKeyMaterial = await globalThis.crypto.subtle.digest(
                    'SHA-256',
                    new TextEncoder().encode(
                        'recipient_sending' + arrayBufferToHex(keyBuffer)
                    )
                )
                sessionKeys.sending = new CryptographyKey(
                    new Uint8Array(sendingKeyMaterial)
                )

                const receivingKeyMaterial = await globalThis.crypto.subtle.digest(
                    'SHA-256',
                    new TextEncoder().encode(
                        'sender_sending' + arrayBufferToHex(keyBuffer)
                    )
                )
                sessionKeys.receiving = new CryptographyKey(
                    new Uint8Array(receivingKeyMaterial)
                )
            } else {
                // We are the sender: we send to them, they receive from us
                const receivingKeyMaterial = await globalThis.crypto.subtle.digest(
                    'SHA-256',
                    new TextEncoder().encode('recipient_sending' +
                        arrayBufferToHex(keyBuffer))
                )
                sessionKeys.receiving = new CryptographyKey(
                    new Uint8Array(receivingKeyMaterial)
                )

                const sendingKeyMaterial = await globalThis.crypto.subtle.digest(
                    'SHA-256',
                    new TextEncoder().encode('sender_sending' +
                        arrayBufferToHex(keyBuffer))
                )
                sessionKeys.sending = new CryptographyKey(
                    new Uint8Array(sendingKeyMaterial)
                )
            }

            // Store serialized keys in IndexedDB
            const serializedKeys:SerializedSessionKeys = {
                sending: Array.from(sessionKeys.sending.getBuffer()),
                receiving: Array.from(sessionKeys.receiving.getBuffer())
            }

            const db = await this.openDB()
            const tx = db.transaction([this.sessionStore], 'readwrite')
            const store = tx.objectStore(this.sessionStore)

            await new Promise<void>((resolve, reject) => {
                const request = store.put(serializedKeys, id)
                request.onerror = () => reject(request.error)
                request.onsuccess = () => resolve()
            })
        } catch {
            // Fail silently for environments without IndexedDB
        }
    }

    /**
     * Get and advance the encryption key for a message (symmetric ratchet).
     */
    async getEncryptionKey (
        id:string,
        recipient?:boolean
    ):Promise<CryptographyKey> {
        try {
            const db = await this.openDB()

            // First transaction: read current keys
            let serializedKeys:SerializedSessionKeys|null
            {
                const tx = db.transaction([this.sessionStore], 'readonly')
                const store = tx.objectStore(this.sessionStore)

                serializedKeys = await new Promise<SerializedSessionKeys | null>((resolve, reject) => {
                    const request = store.get(id)
                    request.onerror = () => reject(request.error)
                    request.onsuccess = () => resolve(request.result)
                })
            }

            if (!serializedKeys) {
                throw new Error('Session key does not exist for client: ' + id)
            }

            // Deserialize keys
            const sessionKeys:SessionKeys = {
                sending: new CryptographyKey(new Uint8Array(serializedKeys.sending)),
                receiving: new CryptographyKey(new Uint8Array(serializedKeys.receiving))
            }

            // Perform symmetric ratchet and get encryption key
            let keys:CryptographyKey[]
            if (recipient) {
                keys = await this.symmetricRatchet(sessionKeys.receiving)
                sessionKeys.receiving = keys[0]
            } else {
                keys = await this.symmetricRatchet(sessionKeys.sending)
                sessionKeys.sending = keys[0]
            }

            // Second transaction: write updated keys
            {
                const tx = db.transaction([this.sessionStore], 'readwrite')
                const store = tx.objectStore(this.sessionStore)

                const updatedSerializedKeys:SerializedSessionKeys = {
                    sending: Array.from(sessionKeys.sending.getBuffer()),
                    receiving: Array.from(sessionKeys.receiving.getBuffer())
                }

                await new Promise<void>((resolve, reject) => {
                    const updateRequest = store.put(updatedSerializedKeys, id)
                    updateRequest.onerror = () => reject(updateRequest.error)
                    updateRequest.onsuccess = () => resolve()
                })
            }

            return keys[1] // Return encryption key
        } catch (error) {
            throw new Error(`Failed to get encryption key for ${id}: ${error}`)
        }
    }

    /**
     * Symmetric ratchet implementation using SHA-256.
     * Returns [nextRatchetKey, encryptionKey].
     */
    private async symmetricRatchet (
        inKey:CryptographyKey
    ):Promise<CryptographyKey[]> {
        const keyBuffer = inKey.getBuffer()
        const fullhash = await globalThis.crypto.subtle.digest(
            'SHA-256',
            new TextEncoder().encode('Symmetric Ratchet' +
                arrayBufferToHex(keyBuffer))
        )

        const hashBytes = new Uint8Array(fullhash)
        return [
            new CryptographyKey(hashBytes.slice(0, 16)), // First 16 bytes for next key
            new CryptographyKey(hashBytes.slice(16, 32)), // Next 16 bytes for encryption
        ]
    }

    /**
     * Delete session keys for a participant.
     */
    async destroySessionKey (id:string):Promise<void> {
        try {
            // Clean up in-memory keys first
            const db = await this.openDB()
            let tx = db.transaction([this.sessionStore], 'readonly')
            const store = tx.objectStore(this.sessionStore)

            const serializedKeys = await new Promise<SerializedSessionKeys | null>((resolve, reject) => {
                const request = store.get(id)
                request.onerror = () => reject(request.error)
                request.onsuccess = () => resolve(request.result)
            })

            if (serializedKeys) {
                const sessionKeys:SessionKeys = {
                    sending: new CryptographyKey(new Uint8Array(serializedKeys.sending)),
                    receiving: new CryptographyKey(new Uint8Array(serializedKeys.receiving))
                }

                await wipe(sessionKeys.sending)
                await wipe(sessionKeys.receiving)
            }

            // Remove from IndexedDB
            tx = db.transaction([this.sessionStore, this.assocDataStore], 'readwrite')
            const sessionStore = tx.objectStore(this.sessionStore)
            const assocStore = tx.objectStore(this.assocDataStore)

            await Promise.all([
                new Promise<void>((resolve, reject) => {
                    const request = sessionStore.delete(id)
                    request.onerror = () => reject(request.error)
                    request.onsuccess = () => resolve()
                }),
                new Promise<void>((resolve, reject) => {
                    const request = assocStore.delete(id)
                    request.onerror = () => reject(request.error)
                    request.onsuccess = () => resolve()
                })
            ])
        } catch {
            // Fail silently for environments without IndexedDB
        }
    }
}

/**
 * In-memory fallback for environments without IndexedDB.
 * Used automatically when IndexedDB is not available.
 */
export class MemorySessionManager {
    private assocData = new Map<string, string>()
    private sessions = new Map<string, SessionKeys>()

    async getAssocData (id:string):Promise<string> {
        return this.assocData.get(id) || ''
    }

    async setAssocData (id:string, assocData:string):Promise<void> {
        this.assocData.set(id, assocData)
    }

    async listSessionIds ():Promise<string[]> {
        return Array.from(this.sessions.keys())
    }

    async setSessionKey (
        id:string,
        key:CryptographyKey,
        recipient?:boolean
    ):Promise<void> {
        this.sessions.set(id, {} as SessionKeys)
        const keyBuffer = key.getBuffer()

        if (recipient) {
            const sendingKeyMaterial = await globalThis.crypto.subtle.digest(
                'SHA-256',
                new TextEncoder().encode(
                    'recipient_sending' + arrayBufferToHex(keyBuffer)
                )
            )
            this.sessions.get(id)!.sending = new CryptographyKey(
                new Uint8Array(sendingKeyMaterial)
            )

            const receivingKeyMaterial = await globalThis.crypto.subtle.digest(
                'SHA-256',
                new TextEncoder().encode(
                    'sender_sending' + arrayBufferToHex(keyBuffer)
                )
            )
            this.sessions.get(id)!.receiving = new CryptographyKey(
                new Uint8Array(receivingKeyMaterial)
            )
        } else {
            const receivingKeyMaterial = await globalThis.crypto.subtle.digest(
                'SHA-256',
                new TextEncoder().encode('recipient_sending' +
                    arrayBufferToHex(keyBuffer))
            )
            this.sessions.get(id)!.receiving = new CryptographyKey(
                new Uint8Array(receivingKeyMaterial)
            )

            const sendingKeyMaterial = await globalThis.crypto.subtle.digest(
                'SHA-256',
                new TextEncoder().encode('sender_sending' +
                    arrayBufferToHex(keyBuffer))
            )
            this.sessions.get(id)!.sending = new CryptographyKey(
                new Uint8Array(sendingKeyMaterial)
            )
        }
    }

    async getEncryptionKey (
        id:string,
        recipient?:boolean
    ):Promise<CryptographyKey> {
        const session = this.sessions.get(id)
        if (!session) {
            throw new Error('Key does not exist for client: ' + id)
        }

        if (recipient) {
            const keys = await this.symmetricRatchet(session.receiving)
            session.receiving = keys[0]
            return keys[1]
        } else {
            const keys = await this.symmetricRatchet(session.sending)
            session.sending = keys[0]
            return keys[1]
        }
    }

    private async symmetricRatchet (
        inKey:CryptographyKey
    ):Promise<CryptographyKey[]> {
        const keyBuffer = inKey.getBuffer()
        const fullhash = await globalThis.crypto.subtle.digest(
            'SHA-256',
            new TextEncoder().encode('Symmetric Ratchet' +
                arrayBufferToHex(keyBuffer))
        )

        const hashBytes = new Uint8Array(fullhash)
        return [
            new CryptographyKey(hashBytes.slice(0, 16)),
            new CryptographyKey(hashBytes.slice(16, 32)),
        ]
    }

    async destroySessionKey (id:string):Promise<void> {
        const session = this.sessions.get(id)
        if (!session) return

        if (session.sending) {
            await wipe(session.sending)
        }
        if (session.receiving) {
            await wipe(session.receiving)
        }
        this.sessions.delete(id)
    }
}

/**
 * Session key manager interface.
 */
export interface SessionKeyManagerInterface {
    getAssocData(id:string):Promise<string>
    getEncryptionKey(id:string, recipient?:boolean):Promise<CryptographyKey>
    destroySessionKey(id:string):Promise<void>
    listSessionIds():Promise<string[]>
    setAssocData(id:string, assocData:string):Promise<void>
    setSessionKey(
        id:string,
        key:CryptographyKey,
        recipient?:boolean
    ):Promise<void>
}

/**
 * Create appropriate session manager based on environment capabilities.
 */
export function createSessionManager ():SessionKeyManagerInterface {
    if (typeof indexedDB !== 'undefined') {
        return new IndexedDBSessionManager()
    } else {
        return new MemorySessionManager()
    }
}
