// End-to-end file encryption: the file is split into chunks, each chunk is
// sealed with AES-256-GCM under a random per-file key, and a BLAKE3 hash of
// every ciphertext chunk goes into a manifest that the server enforces on
// upload. The file key and the manifest hash travel only inside the
// encrypted channel, so the server can neither read nor substitute content.
import { blake3 } from "@noble/hashes/blake3.js"
import { b64, concat, equal, random, u32, u64, unb64 } from "./bytes"
import * as api from "./api"

export interface FileRef {
  t: "file"
  id: string
  name: string
  mime: string
  size: number
  key: string
  manifest: string
}

function manifestHash(hashes: Uint8Array[]): Uint8Array {
  const h = blake3.create({ dkLen: 32 })
  hashes.forEach((c, i) => h.update(u64(i)).update(c))
  return h.digest()
}

async function aesKey(raw: Uint8Array, usage: KeyUsage): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", raw, "AES-GCM", false, [usage])
}

const aad = (i: number, total: number) => concat(u32(i), u32(total))

export async function upload(channelId: string, file: File, chunkSize: number, onProgress: (done: number, total: number) => void): Promise<FileRef> {
  if (file.size === 0) throw new Error("cannot send an empty file")
  const raw = random(32)
  const key = await aesKey(raw, "encrypt")
  const total = Math.ceil(file.size / chunkSize)
  // Pass 1: encrypt to learn the ciphertext hashes for the manifest.
  const chunks: Uint8Array[] = []
  const hashes: Uint8Array[] = []
  for (let i = 0; i < total; i++) {
    const pt = new Uint8Array(await file.slice(i * chunkSize, (i + 1) * chunkSize).arrayBuffer())
    const iv = random(12)
    const ct = concat(iv, new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: aad(i, total) }, key, pt)))
    chunks.push(ct)
    hashes.push(blake3(ct))
  }
  const created = await api.post<{ id: string; manifest_hash: string }>("/api/files", {
    channel_id: channelId, total_size: file.size, chunk_size: chunkSize, chunk_hashes: hashes.map(b64), classification: 0,
  })
  const mh = manifestHash(hashes)
  if (!equal(unb64(created.manifest_hash), mh)) throw new Error("server manifest hash differs from local manifest")
  for (let i = 0; i < total; i++) {
    await api.putBytes(`/api/files/${created.id}/chunks/${i}`, chunks[i])
    onProgress(i + 1, total)
  }
  await api.post(`/api/files/${created.id}/complete`)
  return { t: "file", id: created.id, name: file.name, mime: file.type || "application/octet-stream", size: file.size, key: b64(raw), manifest: b64(mh) }
}

export async function download(ref: FileRef, purpose: string, onProgress: (done: number, total: number) => void): Promise<Blob> {
  const meta = await api.get<{ chunk_count: number; chunk_hashes: string[] }>(`/api/files/${ref.id}`)
  const hashes = meta.chunk_hashes.map(unb64)
  // The manifest hash came through the E2E channel: the server's chunk list
  // must reproduce it exactly.
  if (!equal(manifestHash(hashes), unb64(ref.manifest))) throw new Error("file manifest does not match the one sent in the encrypted channel")
  const key = await aesKey(unb64(ref.key), "decrypt")
  const parts: Uint8Array[] = []
  const q = purpose ? "?purpose=" + encodeURIComponent(purpose) : ""
  for (let i = 0; i < meta.chunk_count; i++) {
    const ct = await api.getBytes(`/api/files/${ref.id}/chunks/${i}${q}`)
    if (!equal(blake3(ct), hashes[i])) throw new Error(`chunk ${i} failed its BLAKE3 integrity check`)
    parts.push(new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: ct.subarray(0, 12), additionalData: aad(i, meta.chunk_count) }, key, ct.subarray(12))))
    onProgress(i + 1, meta.chunk_count)
  }
  return new Blob(parts as BlobPart[], { type: ref.mime })
}
