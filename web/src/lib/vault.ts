// Local vault. Everything the client keeps on disk (MLS group state,
// ratchet sessions, private key packages, decrypted history) is stored in
// IndexedDB encrypted with AES-256-GCM under a non-extractable WebCrypto
// key, so the browser profile on disk never contains plaintext or raw keys.
import { openDB, type IDBPDatabase } from "idb"
import { concat, random, td, te } from "./bytes"

let dbp: Promise<IDBPDatabase> | null = null

function db(): Promise<IDBPDatabase> {
  dbp ??= openDB("siepmu", 1, {
    upgrade(d) {
      d.createObjectStore("keys") // CryptoKey objects (non-extractable)
      d.createObjectStore("vault") // encrypted blobs
    },
  })
  return dbp
}

export async function getKey<T = CryptoKey | CryptoKeyPair>(name: string): Promise<T | undefined> {
  return (await db()).get("keys", name)
}

export async function putKey(name: string, key: CryptoKey | CryptoKeyPair): Promise<void> {
  await (await db()).put("keys", key, name)
}

async function vaultKey(): Promise<CryptoKey> {
  let k = await getKey<CryptoKey>("vault")
  if (!k) {
    k = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"])
    await putKey("vault", k)
  }
  return k
}

/** Serialises values containing Uint8Array and bigint. */
export function encodeJSON(v: unknown): string {
  return JSON.stringify(v, (_k, x) => {
    if (x instanceof Uint8Array) return { $b: btoa(String.fromCharCode(...x)) }
    if (typeof x === "bigint") return { $n: x.toString() }
    return x
  })
}

export function decodeJSON<T>(s: string): T {
  return JSON.parse(s, (_k, x) => {
    if (x && typeof x === "object") {
      if (typeof x.$b === "string") return Uint8Array.from(atob(x.$b), (c) => c.charCodeAt(0))
      if (typeof x.$n === "string") return BigInt(x.$n)
    }
    return x
  })
}

export async function put(name: string, value: unknown): Promise<void> {
  const iv = random(12)
  const pt = value instanceof Uint8Array ? concat(new Uint8Array([1]), value) : concat(new Uint8Array([0]), te.encode(encodeJSON(value)))
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: te.encode(name) }, await vaultKey(), pt))
  await (await db()).put("vault", concat(iv, ct), name)
}

export async function get<T>(name: string): Promise<T | undefined> {
  const blob: Uint8Array | undefined = await (await db()).get("vault", name)
  if (!blob) return undefined
  const pt = new Uint8Array(
    await crypto.subtle.decrypt({ name: "AES-GCM", iv: blob.subarray(0, 12), additionalData: te.encode(name) }, await vaultKey(), blob.subarray(12)),
  )
  return (pt[0] === 1 ? pt.subarray(1) : decodeJSON(td.decode(pt.subarray(1)))) as T
}

export async function del(name: string): Promise<void> {
  await (await db()).delete("vault", name)
}

export async function keysWithPrefix(prefix: string): Promise<string[]> {
  const all = (await (await db()).getAllKeys("vault")) as string[]
  return all.filter((k) => k.startsWith(prefix))
}

/** Serialises read-modify-write sequences on one vault entry. */
const chains = new Map<string, Promise<unknown>>()
export function locked<T>(name: string, fn: () => Promise<T>): Promise<T> {
  const next = (chains.get(name) ?? Promise.resolve()).then(fn, fn)
  chains.set(
    name,
    next.catch(() => undefined),
  )
  return next
}

/** Wipes all local state (sign-out with "forget this device"). */
export async function wipe(): Promise<void> {
  const d = await db()
  await d.clear("vault")
  await d.clear("keys")
}
