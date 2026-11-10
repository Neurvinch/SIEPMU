// Device key and DPoP proofs (RFC 9449). The device key is an ECDSA P-256
// key generated as non-extractable: the browser can sign with it but no
// script (including this one) can read the private key.
import { b64url, te } from "./bytes"
import { getKey, putKey } from "./vault"

let cached: { pair: CryptoKeyPair; jwk: JsonWebKey } | null = null

export async function deviceKey(): Promise<{ pair: CryptoKeyPair; jwk: JsonWebKey }> {
  if (cached) return cached
  let pair = await getKey<CryptoKeyPair>("device")
  if (!pair) {
    pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"])
    await putKey("device", pair)
  }
  const full = await crypto.subtle.exportKey("jwk", pair.publicKey)
  cached = { pair, jwk: { kty: full.kty, crv: full.crv, x: full.x, y: full.y } }
  return cached
}

const enc = (o: unknown) => b64url(te.encode(JSON.stringify(o)))

async function sha256url(data: Uint8Array | string): Promise<string> {
  const bytes = typeof data === "string" ? te.encode(data) : data
  return b64url(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)))
}

/**
 * Builds a DPoP proof for one request. `ath` binds the proof to the access
 * token; `bh` (a SIEPMU extension claim) binds it to the request body, which
 * makes every state-changing request individually signed by the device.
 */
export async function dpopProof(method: string, url: string, accessToken?: string, body?: string): Promise<string> {
  const { pair, jwk } = await deviceKey()
  const u = new URL(url, location.origin)
  const claims: Record<string, unknown> = {
    jti: crypto.randomUUID(),
    htm: method,
    htu: u.origin + u.pathname,
    iat: Math.floor(Date.now() / 1000),
  }
  if (accessToken) claims.ath = await sha256url(accessToken)
  if (body !== undefined) claims.bh = await sha256url(body)
  const input = enc({ typ: "dpop+jwt", alg: "ES256", jwk }) + "." + enc(claims)
  const sig = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, pair.privateKey, te.encode(input)))
  return input + "." + b64url(sig)
}
