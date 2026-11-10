// Authenticated API client. Every request carries a DPoP proof made with the
// device key; requests with a JSON body are additionally body-bound.
import { startAuthentication, startRegistration } from "@simplewebauthn/browser"
import { dpopProof } from "./device"
import * as vault from "./vault"

export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
    public reasons: string[] = [],
  ) {
    super(message)
  }
}

export interface User {
  id: string
  service_number: string
  full_name: string
  rank: string
  unit: string
  clearance: number
  compartments: string[]
  roles: string[]
  status: string
}

let accessToken: string | null = null
let expiresAt = 0
let refreshing: Promise<void> | null = null
let geo: string | null = null
let onSessionLost: (() => void) | null = null

export function setSessionLostHandler(fn: () => void) {
  onSessionLost = fn
}

/** Reports position for geofence posture when the user has allowed it. */
export function enableGeolocation() {
  if (!("geolocation" in navigator)) return
  navigator.geolocation.getCurrentPosition(
    (p) => (geo = `${p.coords.latitude.toFixed(4)},${p.coords.longitude.toFixed(4)}`),
    () => (geo = null),
    { maximumAge: 600_000, timeout: 10_000 },
  )
}

async function parse(res: Response): Promise<any> {
  if (res.status === 204) return undefined
  const ct = res.headers.get("content-type") ?? ""
  if (!res.ok) {
    const j = ct.includes("json") ? await res.json() : { error: "http_" + res.status, message: res.statusText }
    throw new ApiError(res.status, j.error, j.message, j.reasons)
  }
  return ct.includes("json") ? res.json() : res.arrayBuffer()
}

async function raw(method: string, path: string, opts: { json?: unknown; bytes?: Uint8Array; token?: string | null } = {}): Promise<any> {
  const headers: Record<string, string> = {}
  let body: BodyInit | undefined
  let bodyStr: string | undefined
  if (opts.json !== undefined) {
    bodyStr = JSON.stringify(opts.json)
    body = bodyStr
    headers["Content-Type"] = "application/json"
  } else if (opts.bytes) {
    body = opts.bytes
    headers["Content-Type"] = "application/octet-stream"
  } else if (method !== "GET" && method !== "DELETE") {
    bodyStr = ""
    body = ""
    headers["Content-Type"] = "application/json"
  }
  headers["DPoP"] = await dpopProof(method, path, opts.token ?? undefined, bodyStr)
  if (opts.token) headers["Authorization"] = "DPoP " + opts.token
  if (geo) headers["X-SIEPMU-Geo"] = geo
  return parse(await fetch(path, { method, headers, body, cache: "no-store" }))
}

function adopt(r: { access_token: string; expires_in: number; refresh_token: string }) {
  accessToken = r.access_token
  expiresAt = Date.now() + (r.expires_in - 30) * 1000
  return vault.put("session/refresh", r.refresh_token)
}

async function refresh(): Promise<void> {
  refreshing ??= (async () => {
    try {
      const rt = await vault.get<string>("session/refresh")
      if (!rt) throw new ApiError(401, "no_session", "not signed in")
      await adopt(await raw("POST", "/api/auth/refresh", { json: { refresh_token: rt } }))
    } finally {
      refreshing = null
    }
  })()
  return refreshing
}

async function token(): Promise<string> {
  if (!accessToken || Date.now() > expiresAt) await refresh()
  return accessToken!
}

export async function api<T = any>(method: string, path: string, json?: unknown): Promise<T> {
  try {
    return await raw(method, path, { json, token: await token() })
  } catch (e) {
    if (e instanceof ApiError && e.status === 401) {
      accessToken = null
      if (["session_revoked", "session_expired", "refresh_reused", "session_invalid", "no_session"].includes(e.code)) {
        await vault.del("session/refresh")
        onSessionLost?.()
      }
    }
    throw e
  }
}

export const get = <T = any>(path: string) => api<T>("GET", path)
export const post = <T = any>(path: string, json?: unknown) => api<T>("POST", path, json)

export async function putBytes(path: string, bytes: Uint8Array, method = "PUT"): Promise<any> {
  return raw(method, path, { bytes, token: await token() })
}

export async function getBytes(path: string): Promise<Uint8Array> {
  return new Uint8Array(await raw("GET", path, { token: await token() }))
}

/** URL for the realtime socket; browsers cannot set headers on WebSockets. */
export async function wsURL(): Promise<string> {
  const t = await token()
  const proof = await dpopProof("GET", "/api/ws", t)
  const u = new URL("/api/ws", location.origin)
  u.protocol = u.protocol === "https:" ? "wss:" : "ws:"
  u.searchParams.set("access_token", t)
  u.searchParams.set("dpop", proof)
  return u.toString()
}

// ---------------------------------------------------------------- sign-in

function deviceLabel(): string {
  const ua = navigator.userAgent
  const os = /Windows/.test(ua) ? "Windows" : /Mac OS/.test(ua) ? "macOS" : /Android/.test(ua) ? "Android" : /Linux/.test(ua) ? "Linux" : "device"
  return `${os} terminal`
}

async function ceremony(path: string, response: unknown): Promise<any> {
  const body = JSON.stringify(response)
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    DPoP: await dpopProof("POST", path.split("?")[0], undefined, body),
    "X-SIEPMU-Device-Label": deviceLabel(),
  }
  if (geo) headers["X-SIEPMU-Geo"] = geo
  return parse(await fetch(path, { method: "POST", headers, body }))
}

async function begin(path: string, json: unknown) {
  return parse(await fetch(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(json) }))
}

export async function enroll(serviceNumber: string, code: string): Promise<{ user: User; device_status: string }> {
  const b = await begin("/api/auth/enroll/begin", { service_number: serviceNumber, enroll_code: code })
  const att = await startRegistration({ optionsJSON: b.options.publicKey })
  const r = await ceremony("/api/auth/enroll/finish?ceremony=" + b.ceremony, att)
  await adopt(r)
  return r
}

export async function login(serviceNumber: string): Promise<{ user: User; device_status: string }> {
  const b = await begin("/api/auth/login/begin", { service_number: serviceNumber })
  const assertion = await startAuthentication({ optionsJSON: b.options.publicKey })
  const r = await ceremony("/api/auth/login/finish?ceremony=" + b.ceremony, assertion)
  await adopt(r)
  return r
}

export async function hasSession(): Promise<boolean> {
  return !!(await vault.get<string>("session/refresh"))
}

export async function logout(): Promise<void> {
  try {
    await post("/api/auth/logout")
  } catch {
    /* session may already be gone */
  }
  accessToken = null
  await vault.del("session/refresh")
}
