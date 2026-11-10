// MLS (RFC 9420) group messaging via the ts-mls library, fixed to
// ciphersuite 0x0057: X-Wing (ML-KEM-768 + X25519) HPKE, AES-256-GCM,
// SHA-512 and ML-DSA-87 signatures.
import {
  acceptAll, createApplicationMessage, createCommit, createGroup, decodeGroupState, decodeMlsMessage, defaultCapabilities, defaultLifetime,
  emptyPskIndex, encodeGroupState, encodeMlsMessage, generateKeyPackageWithKey, getCiphersuiteFromName, getCiphersuiteImpl, joinGroup,
  processMessage, zeroOutUint8Array,
  type CiphersuiteImpl, type ClientState, type KeyPackage, type PrivateKeyPackage, type Proposal,
} from "ts-mls"
import { b64, td, te } from "./bytes"
import * as vault from "./vault"

export const CIPHER_SUITE = 87
const SUITE_NAME = "MLS_256_XWING_AES256GCM_SHA512_MLDSA87"

let implP: Promise<CiphersuiteImpl> | null = null
const impl = () => (implP ??= getCiphersuiteImpl(getCiphersuiteFromName(SUITE_NAME)))

interface SigKey {
  signKey: Uint8Array
  publicKey: Uint8Array
}

/** The device's long-term MLS signature key (ML-DSA-87). */
async function signatureKey(): Promise<SigKey> {
  let k = await vault.get<SigKey>("mls/sigkey")
  if (!k) {
    k = await (await impl()).signature.keygen()
    await vault.put("mls/sigkey", k)
  }
  return k
}

interface StoredKP {
  pub: Uint8Array // encoded MLSMessage(KeyPackage)
  priv: PrivateKeyPackage
}

const encodeKP = (kp: KeyPackage) => encodeMlsMessage({ keyPackage: kp, wireformat: "mls_key_package", version: "mls10" })

function decodeKP(bytes: Uint8Array): KeyPackage {
  const m = decodeMlsMessage(bytes, 0)?.[0]
  if (!m || m.wireformat !== "mls_key_package") throw new Error("not an MLS KeyPackage")
  return m.keyPackage
}

async function newKeyPackage(userId: string): Promise<StoredKP & { publicPackage: KeyPackage }> {
  const kp = await generateKeyPackageWithKey({ credentialType: "basic", identity: te.encode(userId) }, defaultCapabilities(), defaultLifetime, [], await signatureKey(), await impl())
  return { pub: encodeKP(kp.publicPackage), priv: kp.privatePackage, publicPackage: kp.publicPackage }
}

/** Generates n KeyPackages, stores their private halves, returns the public halves (base64). */
export async function generateKeyPackages(userId: string, n: number): Promise<string[]> {
  const out: string[] = []
  for (let i = 0; i < n; i++) {
    const kp = await newKeyPackage(userId)
    await vault.put("mls/kp/" + crypto.randomUUID(), { pub: kp.pub, priv: kp.priv } satisfies StoredKP)
    out.push(b64(kp.pub))
  }
  return out
}

export async function loadState(channelId: string): Promise<ClientState | undefined> {
  const bytes = await vault.get<Uint8Array>("mls/state/" + channelId)
  if (!bytes) return undefined
  const d = decodeGroupState(bytes, 0)
  if (!d) throw new Error("stored MLS state is corrupt")
  return { ...d[0], clientConfig: (await createEmpty()).clientConfig }
}

// decodeGroupState returns the group state without the client configuration;
// a throwaway group supplies the library defaults.
let emptyP: Promise<ClientState> | null = null
function createEmpty(): Promise<ClientState> {
  return (emptyP ??= (async () => {
    const kp = await newKeyPackage("config")
    return createGroup(te.encode("config"), kp.publicPackage, kp.priv, [], await impl())
  })())
}

export async function saveState(channelId: string, s: ClientState): Promise<void> {
  await vault.put("mls/state/" + channelId, encodeGroupState(s))
}

export async function dropState(channelId: string): Promise<void> {
  await vault.del("mls/state/" + channelId)
}

export async function create(channelId: string, userId: string): Promise<ClientState> {
  const kp = await newKeyPackage(userId)
  return createGroup(te.encode(channelId), kp.publicPackage, kp.priv, [], await impl())
}

/** Identities (user ids) of the current group members. */
export function members(s: ClientState): { userId: string; leaf: number }[] {
  const out: { userId: string; leaf: number }[] = []
  s.ratchetTree.forEach((n, i) => {
    if (n && n.nodeType === "leaf" && n.leaf.credential.credentialType === "basic") out.push({ userId: td.decode(n.leaf.credential.identity), leaf: i / 2 })
  })
  return out
}

export const epoch = (s: ClientState) => Number(s.groupContext.epoch)

export interface CommitOut {
  newState: ClientState
  commit: Uint8Array
  welcome?: Uint8Array
}

/**
 * Commits membership changes. `adds` maps user id to that user's KeyPackage
 * (base64); the credential inside the KeyPackage must name the same user.
 */
export async function commitChanges(s: ClientState, adds: Record<string, string>, removeUserIds: string[]): Promise<CommitOut> {
  const proposals: Proposal[] = []
  for (const [userId, kpB64] of Object.entries(adds)) {
    const kp = decodeKP(Uint8Array.from(atob(kpB64), (c) => c.charCodeAt(0)))
    const cred = kp.leafNode.credential
    if (cred.credentialType !== "basic" || td.decode(cred.identity) !== userId) throw new Error("KeyPackage credential does not match user " + userId)
    proposals.push({ proposalType: "add", add: { keyPackage: kp } })
  }
  const current = members(s)
  for (const uid of removeUserIds) for (const m of current.filter((x) => x.userId === uid)) proposals.push({ proposalType: "remove", remove: { removed: m.leaf } })
  const r = await createCommit({ state: s, cipherSuite: await impl() }, { extraProposals: proposals, ratchetTreeExtension: true })
  r.consumed.forEach(zeroOutUint8Array)
  return {
    newState: r.newState,
    commit: encodeMlsMessage(r.commit),
    welcome: r.welcome ? encodeMlsMessage({ welcome: r.welcome, wireformat: "mls_welcome", version: "mls10" }) : undefined,
  }
}

/** Joins from a Welcome using whichever stored KeyPackage it was issued for. */
export async function join(welcomeBytes: Uint8Array): Promise<ClientState> {
  const m = decodeMlsMessage(welcomeBytes, 0)?.[0]
  if (!m || m.wireformat !== "mls_welcome") throw new Error("not an MLS Welcome")
  for (const key of await vault.keysWithPrefix("mls/kp/")) {
    const kp = await vault.get<StoredKP>(key)
    if (!kp) continue
    try {
      const s = await joinGroup(m.welcome, decodeKP(kp.pub), kp.priv, emptyPskIndex, await impl())
      await vault.del(key) // init key is single-use (forward secrecy)
      return s
    } catch {
      /* this Welcome was not for this KeyPackage */
    }
  }
  throw new Error("no stored KeyPackage matches this Welcome")
}

export async function encrypt(s: ClientState, plaintext: Uint8Array): Promise<{ newState: ClientState; message: Uint8Array }> {
  const r = await createApplicationMessage(s, plaintext, await impl())
  r.consumed.forEach(zeroOutUint8Array)
  return { newState: r.newState, message: encodeMlsMessage({ privateMessage: r.privateMessage, wireformat: "mls_private_message", version: "mls10" }) }
}

/** Processes a commit, proposal or application message from another member. */
export async function receive(s: ClientState, bytes: Uint8Array): Promise<{ newState: ClientState; plaintext?: Uint8Array }> {
  const m = decodeMlsMessage(bytes, 0)?.[0]
  if (!m || (m.wireformat !== "mls_private_message" && m.wireformat !== "mls_public_message")) throw new Error("unexpected MLS wire format")
  const r = await processMessage(m, s, emptyPskIndex, acceptAll, await impl())
  r.consumed.forEach(zeroOutUint8Array)
  return { newState: r.newState, plaintext: r.kind === "applicationMessage" ? r.message : undefined }
}
