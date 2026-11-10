import { describe, expect, it } from "vitest"
import { td, te } from "./bytes"
import * as R from "./ratchet"

function setup() {
  const alice = R.newIdentity()
  const bob = R.newIdentity()
  const spk = R.newSignedPrekey(bob, 7)
  const otk = R.newOneTimePrekey(99)
  const bundle: R.Bundle = { identity_sig_pub: bob.sigPub, signed_prekey: spk.pub, signed_prekey_id: 7, signed_prekey_sig: spk.sig, one_time_prekey_id: 99, one_time_prekey: otk.pub }
  const a = R.initiate(alice, bundle)
  const first = R.encrypt(a, te.encode("hello bob"))
  const b = R.respond(bob, first, (id) => (id === 7 ? spk.secret : undefined), (id) => (id === 99 ? otk.secret : undefined))
  return { alice, bob, a, b, first, bundle, spk, otk }
}
const wire = (e: R.Envelope): R.Envelope => JSON.parse(JSON.stringify(e))

describe("double ratchet", () => {
  it("runs a conversation with DH ratchet steps in both directions", () => {
    const { a, b, first } = setup()
    expect(td.decode(R.decrypt(b, wire(first)))).toBe("hello bob")
    expect(a.pendingInit).toBeDefined()
    expect(td.decode(R.decrypt(a, wire(R.encrypt(b, te.encode("hi alice")))))).toBe("hi alice")
    expect(a.pendingInit).toBeUndefined()
    for (let i = 0; i < 20; i++) {
      const [s, r] = i % 3 === 0 ? [b, a] : [a, b]
      expect(td.decode(R.decrypt(r, wire(R.encrypt(s, te.encode("m" + i)))))).toBe("m" + i)
    }
  })

  it("handles out-of-order and lost messages", () => {
    const { a, b, first } = setup()
    R.decrypt(b, first)
    const m1 = R.encrypt(a, te.encode("1"))
    const m2 = R.encrypt(a, te.encode("2"))
    const m3 = R.encrypt(a, te.encode("3"))
    expect(td.decode(R.decrypt(b, m3))).toBe("3")
    const reply = R.encrypt(b, te.encode("r"))
    expect(td.decode(R.decrypt(a, reply))).toBe("r")
    const m4 = R.encrypt(a, te.encode("4")) // new DH ratchet
    expect(td.decode(R.decrypt(b, m4))).toBe("4")
    expect(td.decode(R.decrypt(b, m1))).toBe("1") // skipped key from the old chain
    expect(td.decode(R.decrypt(b, m2))).toBe("2")
    expect(() => R.decrypt(b, m2)).toThrow() // replay
  })

  it("rejects tampering and leaves the session usable", () => {
    const { a, b, first } = setup()
    R.decrypt(b, first)
    const m = R.encrypt(a, te.encode("x"))
    const bad = wire(m)
    bad.h.n = 5
    expect(() => R.decrypt(b, bad)).toThrow()
    const bad2 = wire(m)
    bad2.c = bad2.c.slice(0, -4) + "AAAA"
    expect(() => R.decrypt(b, bad2)).toThrow()
    expect(td.decode(R.decrypt(b, m))).toBe("x")
  })

  it("gives forward secrecy: old state cannot read later epochs, new state cannot re-read old messages", () => {
    const { a, b, first } = setup()
    R.decrypt(b, first)
    const snapshot = structuredClone(b)
    const m1 = R.encrypt(a, te.encode("before"))
    R.decrypt(b, m1)
    R.decrypt(a, R.encrypt(b, te.encode("ratchet")))
    const m2 = R.encrypt(a, te.encode("after"))
    R.decrypt(b, m2)
    expect(() => R.decrypt(b, m1)).toThrow() // message key deleted after use
    // Post-compromise security: an attacker holding a snapshot of bob's state
    // can follow passively only until bob sends with a fresh DH key.
    const attacker = structuredClone(snapshot)
    expect(td.decode(R.decrypt(attacker, m1))).toBe("before")
    expect(td.decode(R.decrypt(attacker, m2))).toBe("after")
    R.decrypt(a, R.encrypt(b, te.encode("bob heals with a new ratchet key")))
    const m3 = R.encrypt(a, te.encode("healed"))
    expect(td.decode(R.decrypt(b, m3))).toBe("healed")
    expect(() => R.decrypt(attacker, m3)).toThrow()
  })

  it("authenticates both parties", () => {
    const { alice, bob, bundle, spk, otk } = setup()
    const mallory = R.newIdentity()
    const forged = { ...bundle, signed_prekey: R.newSignedPrekey(mallory, 7).pub }
    expect(() => R.initiate(alice, forged)).toThrow(/signature/)
    const a = R.initiate(alice, bundle)
    const env = wire(R.encrypt(a, te.encode("hi")))
    env.h.init!.ik = btoa(String.fromCharCode(...mallory.sigPub)) // claim to be someone else
    expect(() => R.respond(bob, env, () => spk.secret, () => otk.secret)).toThrow(/signature/)
  })

  it("derives the same safety number on both sides", () => {
    const { alice, bob } = setup()
    expect(R.safetyNumber(alice.sigPub, bob.sigPub)).toBe(R.safetyNumber(bob.sigPub, alice.sigPub))
    expect(R.safetyNumber(alice.sigPub, bob.sigPub)).toMatch(/^(\d{5} ){5}\d{5}$/)
  })
})
