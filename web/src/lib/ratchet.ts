// Double Ratchet for 1:1 sessions, following Signal's published
// specification (https://signal.org/docs/specifications/doubleratchet/),
// with a post-quantum initial key agreement in the style of PQXDH:
//
//   * identity keys are ML-DSA-65 (FIPS 204) signature keys;
//   * the signed prekey and one-time prekeys are X-Wing hybrid KEM keys
//     (ML-KEM-768 + X25519); the initial root key is derived from the KEM
//     shared secrets, so recorded traffic stays confidential against a
//     future quantum adversary (harvest-now-decrypt-later);
//   * the per-message DH ratchet uses X25519 and provides forward secrecy
//     and post-compromise recovery exactly as in the Signal design.
//
// Primitives come from the audited noble libraries; only the protocol state
// machine is implemented here.
import { gcm } from "@noble/ciphers/aes.js"
import { x25519 } from "@noble/curves/ed25519.js"
import { hkdf } from "@noble/hashes/hkdf.js"
import { hmac } from "@noble/hashes/hmac.js"
import { sha256 } from "@noble/hashes/sha2.js"
import { XWing } from "@noble/post-quantum/hybrid.js"
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js"
import { b64, concat, equal, random, te, u32, unb64 } from "./bytes"

const INFO = te.encode("SIEPMU-DR-v1")
const SIG_CTX = { context: te.encode("SIEPMU-DR-v1/prekey") }
const INIT_CTX = { context: te.encode("SIEPMU-DR-v1/init") }
const MAX_SKIP = 500
const XWING_PUB = 1216

export interface Identity {
  sigPub: Uint8Array
  sigKey: Uint8Array
}

export interface PrekeySecret {
  id: number
  kemSecret: Uint8Array
  /** Only the signed prekey carries an X25519 ratchet key. */
  dhSecret?: Uint8Array
  dhPub?: Uint8Array
}

export interface Bundle {
  identity_sig_pub: Uint8Array
  signed_prekey: Uint8Array // X-Wing public key || X25519 ratchet public key
  signed_prekey_id: number
  signed_prekey_sig: Uint8Array
  one_time_prekey_id?: number
  one_time_prekey?: Uint8Array
}

export function newIdentity(): Identity {
  const k = ml_dsa65.keygen()
  return { sigPub: k.publicKey, sigKey: k.secretKey }
}

export function newSignedPrekey(id: Identity, keyId: number): { pub: Uint8Array; sig: Uint8Array; secret: PrekeySecret } {
  const kem = XWing.keygen()
  const dh = x25519.keygen()
  const pub = concat(kem.publicKey, dh.publicKey)
  return { pub, sig: ml_dsa65.sign(pub, id.sigKey, SIG_CTX), secret: { id: keyId, kemSecret: kem.secretKey, dhSecret: dh.secretKey, dhPub: dh.publicKey } }
}

export function newOneTimePrekey(keyId: number): { pub: Uint8Array; secret: PrekeySecret } {
  const kem = XWing.keygen()
  return { pub: kem.publicKey, secret: { id: keyId, kemSecret: kem.secretKey } }
}

interface InitBlock {
  ik: string // initiator identity public key
  spk: number
  otk?: number
  ct1: string
  ct2?: string
  sig: string
}

interface Header {
  dh: string
  pn: number
  n: number
  init?: InitBlock
}

export interface Envelope {
  h: Header
  c: string
}

export interface Session {
  ad: Uint8Array
  rk: Uint8Array
  dhsSecret: Uint8Array
  dhsPub: Uint8Array
  dhr?: Uint8Array
  cks?: Uint8Array
  ckr?: Uint8Array
  ns: number
  nr: number
  pn: number
  skipped: Record<string, Uint8Array>
  /** Present on the initiator until the first reply arrives. */
  pendingInit?: InitBlock
  peerIdentity: Uint8Array
}

function kdfRK(rk: Uint8Array, dhOut: Uint8Array): [Uint8Array, Uint8Array] {
  const out = hkdf(sha256, dhOut, rk, INFO, 64)
  return [out.subarray(0, 32), out.subarray(32)]
}

function kdfCK(ck: Uint8Array): [Uint8Array, Uint8Array] {
  return [hmac(sha256, ck, new Uint8Array([2])), hmac(sha256, ck, new Uint8Array([1]))] // [next chain key, message key]
}

function headerBytes(h: Header): Uint8Array {
  return concat(unb64(h.dh), u32(h.pn), u32(h.n), te.encode(h.init ? JSON.stringify(h.init) : ""))
}

function seal(mk: Uint8Array, plaintext: Uint8Array, aad: Uint8Array): Uint8Array {
  const okm = hkdf(sha256, mk, new Uint8Array(32), te.encode("SIEPMU-DR-v1/msg"), 44)
  return gcm(okm.subarray(0, 32), okm.subarray(32), aad).encrypt(plaintext)
}

function open(mk: Uint8Array, ct: Uint8Array, aad: Uint8Array): Uint8Array {
  const okm = hkdf(sha256, mk, new Uint8Array(32), te.encode("SIEPMU-DR-v1/msg"), 44)
  return gcm(okm.subarray(0, 32), okm.subarray(32), aad).decrypt(ct)
}

function associatedData(initiatorIK: Uint8Array, responderIK: Uint8Array): Uint8Array {
  return concat(sha256(initiatorIK), sha256(responderIK))
}

function initialSecret(ss1: Uint8Array, ss2: Uint8Array | undefined, ad: Uint8Array): Uint8Array {
  return hkdf(sha256, ss2 ? concat(ss1, ss2) : ss1, new Uint8Array(32), concat(INFO, ad), 32)
}

function initSigInput(b: Omit<InitBlock, "sig">, dhPub: Uint8Array, responderIK: Uint8Array): Uint8Array {
  return concat(unb64(b.ct1), b.ct2 ? unb64(b.ct2) : new Uint8Array(), u32(b.spk), u32(b.otk ?? 0xffffffff), dhPub, sha256(responderIK))
}

/** Verifies a prekey bundle's signature; throws if it does not verify. */
export function verifyBundle(b: Bundle): void {
  if (b.signed_prekey.length !== XWING_PUB + 32 || !ml_dsa65.verify(b.signed_prekey_sig, b.signed_prekey, b.identity_sig_pub, SIG_CTX))
    throw new Error("prekey bundle signature is invalid")
}

/** Initiator: start a session from the peer's verified bundle. */
export function initiate(me: Identity, bundle: Bundle): Session {
  verifyBundle(bundle)
  // noble may wipe its inputs, so every key handed to it is a private copy.
  const kemPub = bundle.signed_prekey.slice(0, XWING_PUB)
  const peerDH = bundle.signed_prekey.slice(XWING_PUB)
  const e1 = XWing.encapsulate(kemPub)
  const e2 = bundle.one_time_prekey ? XWing.encapsulate(bundle.one_time_prekey.slice()) : undefined
  const ad = associatedData(me.sigPub, bundle.identity_sig_pub)
  const sk = initialSecret(e1.sharedSecret, e2?.sharedSecret, ad)
  const dhs = x25519.keygen()
  const [rk, cks] = kdfRK(sk, x25519.getSharedSecret(dhs.secretKey, peerDH))
  const partial = {
    ik: b64(me.sigPub),
    spk: bundle.signed_prekey_id,
    otk: e2 ? bundle.one_time_prekey_id : undefined,
    ct1: b64(e1.cipherText),
    ct2: e2 ? b64(e2.cipherText) : undefined,
  }
  const sig = ml_dsa65.sign(initSigInput(partial, dhs.publicKey, bundle.identity_sig_pub), me.sigKey, INIT_CTX)
  return {
    ad, rk, cks, dhsSecret: dhs.secretKey, dhsPub: dhs.publicKey, dhr: bundle.signed_prekey.slice(XWING_PUB), ns: 0, nr: 0, pn: 0, skipped: {},
    pendingInit: { ...partial, sig: b64(sig) }, peerIdentity: bundle.identity_sig_pub,
  }
}

/** True if the envelope starts a new session. */
export const isInitial = (env: Envelope) => !!env.h.init

/**
 * Responder: build a session from the first message of an initiator.
 * `lookup` returns the secret for a prekey id (one-time prekeys must be
 * deleted by the caller once the session is stored).
 */
export function respond(me: Identity, env: Envelope, signedPrekey: (id: number) => PrekeySecret | undefined, oneTime: (id: number) => PrekeySecret | undefined): Session {
  const init = env.h.init
  if (!init) throw new Error("not an initial message")
  const initiatorIK = unb64(init.ik)
  const dhPub = unb64(env.h.dh)
  const { sig, ...partial } = init
  if (!ml_dsa65.verify(unb64(sig), initSigInput(partial, dhPub, me.sigPub), initiatorIK, INIT_CTX)) throw new Error("initial message signature is invalid")
  const spk = signedPrekey(init.spk)
  if (!spk?.dhSecret || !spk.dhPub) throw new Error("unknown signed prekey " + init.spk)
  const ss1 = XWing.decapsulate(unb64(init.ct1), spk.kemSecret.slice())
  let ss2: Uint8Array | undefined
  if (init.ct2 !== undefined) {
    const otk = init.otk !== undefined ? oneTime(init.otk) : undefined
    if (!otk) throw new Error("one-time prekey already used or unknown")
    ss2 = XWing.decapsulate(unb64(init.ct2), otk.kemSecret.slice())
  }
  const ad = associatedData(initiatorIK, me.sigPub)
  return { ad, rk: initialSecret(ss1, ss2, ad), dhsSecret: spk.dhSecret, dhsPub: spk.dhPub, ns: 0, nr: 0, pn: 0, skipped: {}, peerIdentity: initiatorIK }
}

export function encrypt(s: Session, plaintext: Uint8Array): Envelope {
  if (!s.cks) throw new Error("session cannot send before receiving the first message")
  const [cks, mk] = kdfCK(s.cks)
  s.cks = cks
  const h: Header = { dh: b64(s.dhsPub), pn: s.pn, n: s.ns, init: s.pendingInit }
  s.ns++
  return { h, c: b64(seal(mk, plaintext, concat(s.ad, headerBytes(h)))) }
}

function skip(s: Session, until: number) {
  if (!s.ckr) return
  if (until - s.nr > MAX_SKIP) throw new Error("too many skipped messages")
  while (s.nr < until) {
    const [ckr, mk] = kdfCK(s.ckr)
    s.ckr = ckr
    s.skipped[b64(s.dhr!) + ":" + s.nr] = mk
    s.nr++
  }
  const keys = Object.keys(s.skipped)
  for (const k of keys.slice(0, Math.max(0, keys.length - 2 * MAX_SKIP))) delete s.skipped[k]
}

/** Decrypts in place; on failure the session is left unchanged. */
export function decrypt(s: Session, env: Envelope): Uint8Array {
  const w: Session = structuredClone(s)
  const aad = concat(w.ad, headerBytes(env.h))
  const ct = unb64(env.c)
  const dh = unb64(env.h.dh)
  const key = env.h.dh + ":" + env.h.n
  let pt: Uint8Array
  if (w.skipped[key]) {
    pt = open(w.skipped[key], ct, aad)
    delete w.skipped[key]
  } else {
    if (!w.dhr || !equal(dh, w.dhr)) {
      skip(w, env.h.pn)
      w.pn = w.ns
      w.ns = 0
      w.nr = 0
      w.dhr = dh
      ;[w.rk, w.ckr] = kdfRK(w.rk, x25519.getSharedSecret(w.dhsSecret, dh))
      const next = x25519.keygen()
      w.dhsSecret = next.secretKey
      w.dhsPub = next.publicKey
      ;[w.rk, w.cks] = kdfRK(w.rk, x25519.getSharedSecret(w.dhsSecret, dh))
    } else if (!w.ckr) {
      // Initiator receiving on the chain it has not derived yet cannot happen:
      // the responder always ratchets first.
      throw new Error("no receiving chain")
    }
    skip(w, env.h.n)
    const [ckr, mk] = kdfCK(w.ckr!)
    w.ckr = ckr
    w.nr++
    pt = open(mk, ct, aad)
  }
  delete w.pendingInit // any authenticated reply acknowledges the handshake
  Object.assign(s, w)
  if (!w.pendingInit) delete s.pendingInit
  return pt
}

/** Human-comparable fingerprint of both identity keys (order-independent). */
export function safetyNumber(a: Uint8Array, b: Uint8Array): string {
  const [x, y] = b64(a) < b64(b) ? [a, b] : [b, a]
  const h = sha256(concat(te.encode("SIEPMU-safety-number"), x, y))
  const digits: string[] = []
  for (let i = 0; i < 30; i += 5) {
    const v = new DataView(h.buffer, h.byteOffset + i, 5)
    digits.push(String((v.getUint32(0) * 256 + v.getUint8(4)) % 100000).padStart(5, "0"))
  }
  return digits.join(" ")
}

export const randomId = () => new DataView(random(4).buffer).getUint32(0) >>> 1
