// Randomized adversarial tests for the rules a Null Chat's tab uses to
// trust records (web/src/room-state.ts). Honest members chat; a malicious
// member, who also controls the server, mixes in forged, altered, replayed,
// re-stamped and out-of-order records, and drops some. After every record,
// the tabs of an honest member and of the creator must still hold:
//
// - nothing throws;
// - only people the creator admitted are members, each with their own keys;
// - every message shown from an honest member is one they sent (or an edit
//   they made), and every reply's quote is the message it names;
// - keys only move forward, and no warning, once raised, goes away.
//
// With no attacker and no tampering, the honest tabs must also read every
// message and raise no warning at all.
//
// Deterministic: fixed seeds, so a failure reproduces exactly. Set
// NB_ROOM_FUZZ_ROUNDS for a longer run.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { loadSodium } from '../src/sodium.ts';
import { sealChained } from './chained.ts';
import {
  MAX_BOX_N,
  REACTIONS,
  NO_ACK,
  boxName,
  chainCommit,
  controlKey,
  encodeKey,
  inviteCheck,
  joinProof,
  newChain,
  newRecordId,
  sealChainKey,
  sealControl,
  sealMessage,
  sealName,
  sealRoster,
  checkJoinProof,
  type Ack,
  type Chain,
  type ControlRecord,
  type MessageRecord,
} from '../src/room-crypto.ts';
import { RoomState } from '../src/room-state.ts';

const sodium = await loadSodium();
const ROOM = 'fedcba9876543210fedcba9876543210';
const ROUNDS = Number(process.env['NB_ROOM_FUZZ_ROUNDS'] ?? '') || 40;

// xorshift32: small, fast and reproducible.
function rng(seed: number) {
  let x = seed >>> 0 || 1;
  const next = () => {
    x ^= x << 13; x >>>= 0;
    x ^= x >>> 17;
    x ^= x << 5; x >>>= 0;
    return x;
  };
  return {
    int: (n: number) => next() % n,
    chance: (p: number) => next() / 0x100000000 < p,
    bytes: (n: number) => Uint8Array.from({ length: n }, () => next() & 0xff),
    pick: <T>(xs: readonly T[]): T => xs[next() % xs.length]!,
  };
}
type Rng = ReturnType<typeof rng>;

interface Person {
  slot: number;
  name: string;
  sign: { publicKey: Uint8Array; privateKey: Uint8Array };
  box: { publicKey: Uint8Array; privateKey: Uint8Array };
}
interface Posted { from: number; bytes: Uint8Array }

const NO_RECEIPTS: Ack[] = Array.from({ length: 20 }, (_, slot) => ({ slot, gen: 0, index: 0, h: NO_ACK }));
const WORDS = ['hello', 'meet at noon', 'ok', 'the code is 4821', 'see you', 'bring the keys', 'done', 'call me'];

/** One room: its people, everything they posted in order, and what each honest one said. */
function scenario(seed: number, hostile: boolean) {
  const r = rng(seed);
  const key = controlKey(sodium, sodium.randombytes_buf(32));
  const roster = sodium.randombytes_buf(32);
  const names = sodium.crypto_box_keypair();
  const person = (slot: number, name: string): Person => ({ slot, name, sign: sodium.crypto_sign_keypair(), box: sodium.crypto_box_keypair() });
  const [ada, bob, cleo, vic, mal] = [person(0, 'Ada'), person(1, 'Bob'), person(2, 'Cleo'), person(3, 'Vic'), person(4, 'Mal')] as const;
  const people = [ada, bob, cleo, vic, mal];
  const secrets = new Map(people.slice(1).map((p) => [p.slot, sodium.randombytes_buf(32)]));
  const log: Posted[] = [];
  const said = new Map<number, Set<string>>(people.map((p) => [p.slot, new Set<string>()]));
  const sent = new Map<number, { id: string; author: number }[]>();
  let clock = 1_000_000;
  const time = () => (clock += 1 + r.int(5_000));
  const ctl = (p: Person, rec: ControlRecord, slot = p.slot) => log.push({ from: slot, bytes: sealControl(sodium, key, ROOM, slot, p.sign.privateKey, rec) });
  const enc = (p: Person) => ({ key: encodeKey(sodium, p.sign.publicKey), box: encodeKey(sodium, p.box.publicKey) });

  // The creator makes the room and invites everyone; they join; it admits them.
  ctl(ada, { t: 'join', id: newRecordId(sodium), time: time(), name: boxName(sodium, roster, ada.name, ROOM, 'member', 0), ...enc(ada), namekey: encodeKey(sodium, names.publicKey) });
  ctl(ada, { t: 'room', id: newRecordId(sodium), time: time(), name: boxName(sodium, roster, 'Plans', ROOM, 'room', 0), ends: clock + 3_600_000, pw: false, max: 20, ttl: 3600 });
  for (const p of people.slice(1)) {
    ctl(ada, { t: 'invite', id: newRecordId(sodium), time: time(), slot: p.slot, label: boxName(sodium, roster, p.name, ROOM, 'label', p.slot), check: inviteCheck(sodium, secrets.get(p.slot)!, ROOM, p.slot), exp: clock + 3_600_000 });
  }
  for (const p of people.slice(1)) {
    const { key: k, box } = enc(p);
    ctl(p, {
      t: 'join', id: newRecordId(sodium), time: time(), key: k, box, proof: joinProof(sodium, secrets.get(p.slot)!, ROOM, p.slot, k, box),
      name: sealName(sodium, p.name, names.publicKey, { roomId: ROOM, slot: p.slot, key: k, box }),
    });
  }
  for (const p of people.slice(1)) {
    ctl(ada, {
      t: 'admit', id: newRecordId(sodium), time: time(), slot: p.slot, key: encodeKey(sodium, p.sign.publicKey),
      roster: sealRoster(sodium, roster, p.box.publicKey, ROOM, p.slot), name: boxName(sodium, roster, p.name, ROOM, 'member', p.slot),
    });
  }

  // Then they chat. Senders: everyone but the victim (whose own records
  // would come back unreadable to it anyway).
  const removed = new Set<number>();
  const chains = new Map<number, Chain & { sent: number }>();
  const senders = [ada, bob, cleo, mal];
  const messages = new Map<number, number>();
  const send = (p: Person, rec: MessageRecord) => {
    let c = chains.get(p.slot);
    if (!c || c.sent >= 50) {
      c = { ...newChain(sodium, (c?.gen ?? 0) + 1), sent: 0 };
      chains.set(p.slot, c);
      const place = { roomId: ROOM, slot: p.slot, gen: c.gen, index: c.index };
      const to = people.filter((q) => q !== p && !removed.has(q.slot)).map((q) => ({ slot: q.slot, n: 0, box: sealChainKey(sodium, c!.ck, q.box.publicKey, place, q.slot) }));
      ctl(p, { t: 'keys', id: newRecordId(sodium), time: time(), gen: c.gen, index: c.index, commit: chainCommit(sodium, c.ck, place), to });
    }
    log.push({ from: p.slot, bytes: sealChained(sodium, c, ROOM, p.slot, p.sign.privateKey, rec) });
    c.sent++;
  };
  const steps = 30 + r.int(60);
  for (let i = 0; i < steps; i++) {
    const p = r.pick(senders.filter((s) => !removed.has(s.slot)));
    const own = sent.get(p.slot) ?? [];
    const all = [...sent.values()].flat();
    const kind = r.int(10);
    if (kind < 6 || own.length === 0) {
      const text = `${r.pick(WORDS)} #${seed}.${i}`;
      const target = all.length > 0 && r.chance(0.3) ? r.pick(all) : null;
      const id = newRecordId(sodium);
      send(p, { t: 'msg', id, time: time(), text, reply: target, seen: NO_RECEIPTS });
      said.get(p.slot)!.add(text);
      own.push({ id, author: p.slot });
      sent.set(p.slot, own);
      messages.set(p.slot, (messages.get(p.slot) ?? 0) + 1);
    } else if (kind < 8) {
      const text = `edited ${r.pick(WORDS)} #${seed}.${i}`;
      send(p, { t: 'edit', id: newRecordId(sodium), time: time(), prev: null, target: r.pick(own).id, text });
      said.get(p.slot)!.add(text);
    } else if (kind < 9) {
      const t = r.pick(all);
      send(p, { t: 'react', id: newRecordId(sodium), time: time(), prev: null, target: t.id, author: t.author, emoji: r.pick(REACTIONS), on: true });
    } else {
      send(p, { t: 'unsend', id: newRecordId(sodium), time: time(), prev: null, target: r.pick(own).id });
    }
    // Once, the creator removes Cleo; everyone starts new chains without her.
    if (!removed.has(2) && i === Math.floor(steps / 2) && r.chance(0.5)) {
      removed.add(2);
      ctl(ada, { t: 'remove', id: newRecordId(sodium), time: time(), slot: 2 });
      for (const c of chains.values()) c.sent = 50;
    }
  }
  return { r, key, roster, names, people, ada, vic, mal, secrets, log, said, sent, messages, removed, hostile, time, chains };
}
type Scenario = ReturnType<typeof scenario>;

/** One record the malicious member, who also runs the server, could make up. */
function forge(s: Scenario): Posted | null {
  const { r, key, mal, ada, vic, log, sent } = s;
  const honest = log[r.int(log.length)]!;
  const all = [...sent.values()].flat();
  const malCtl = (rec: ControlRecord, slot = mal.slot): Posted => ({ from: slot, bytes: sealControl(sodium, key, ROOM, slot, mal.sign.privateKey, rec) });
  // Mostly the chain Mal really shares, so the forgeries can be read and
  // must be judged on what they say; sometimes one nobody has.
  const real = s.chains.get(mal.slot);
  const malChain = real && r.chance(0.8) ? real : newChain(sodium, 1 + r.int(3));
  const malMsg = (rec: MessageRecord, slot = mal.slot): Posted => ({ from: slot, bytes: sealChained(sodium, malChain, ROOM, slot, mal.sign.privateKey, rec) });
  const id = () => newRecordId(sodium);
  const k = encodeKey(sodium, mal.sign.publicKey);
  const b = encodeKey(sodium, mal.box.publicKey);
  switch (r.int(20)) {
    case 0: return { from: r.int(20), bytes: r.bytes(r.int(2_000)) };
    case 1: { // flip a bit
      const bytes = honest.bytes.slice();
      bytes[r.int(bytes.length)]! ^= 1 << r.int(8);
      return { from: honest.from, bytes };
    }
    case 2: return { from: (honest.from + 1 + r.int(19)) % 20, bytes: honest.bytes }; // stamped as someone else
    case 3: return { from: honest.from, bytes: honest.bytes.slice(0, r.int(honest.bytes.length)) }; // cut
    case 4: return malCtl({ t: 'admit', id: id(), time: s.time(), slot: 5 + r.int(15), key: k, roster: sealRoster(sodium, s.roster, mal.box.publicKey, ROOM, 5), name: boxName(sodium, s.roster, 'Ada', ROOM, 'member', 5) });
    case 5: return malCtl({ t: 'remove', id: id(), time: s.time(), slot: 1 + r.int(3) });
    case 6: return malCtl({ t: 'invite', id: id(), time: s.time(), slot: 3, label: boxName(sodium, s.roster, 'Vic', ROOM, 'label', 3), check: encodeKey(sodium, r.bytes(32)), exp: s.time() + 60_000 });
    case 7: return malCtl({ t: 'room', id: id(), time: s.time(), name: boxName(sodium, s.roster, 'Other', ROOM, 'room', 0), ends: 1, pw: true, max: 2, ttl: 300 });
    case 8: return malCtl({ t: 'box', id: id(), time: s.time(), n: r.pick([1, 2, 65, 1000, MAX_BOX_N]), box: encodeKey(sodium, sodium.crypto_box_keypair().publicKey) });
    case 9: { // keys for the victim sealed to a key it never had, or a commitment that does not match
      const place = { roomId: ROOM, slot: mal.slot, gen: malChain.gen, index: malChain.index };
      const junk = sodium.crypto_box_keypair().publicKey;
      return malCtl({
        t: 'keys', id: id(), time: s.time(), gen: malChain.gen, index: malChain.index + r.int(300),
        commit: r.chance(0.5) ? chainCommit(sodium, malChain.ck, place) : encodeKey(sodium, r.bytes(32)),
        to: [{ slot: vic.slot, n: r.int(3), box: sealChainKey(sodium, malChain.ck, r.chance(0.5) ? vic.box.publicKey : junk, place, vic.slot) }],
      });
    }
    case 10: return malCtl({ t: 'join', id: id(), time: s.time(), key: k, box: b, name: sealName(sodium, 'Ada', s.names.publicKey, { roomId: ROOM, slot: 0, key: k, box: b }) }, 5 + r.int(15));
    case 11: // posing as the creator: signed by Mal, posted at the creator's place
      return malCtl({ t: 'join', id: id(), time: s.time(), name: boxName(sodium, s.roster, 'Ada', ROOM, 'member', 0), key: k, box: b, namekey: encodeKey(sodium, s.names.publicKey) }, 0);
    case 12: return malCtl({ t: 'admit', id: id(), time: s.time(), slot: 1, key: k, roster: sealRoster(sodium, s.roster, mal.box.publicKey, ROOM, 1), name: boxName(sodium, s.roster, 'Bob', ROOM, 'member', 1) }, 0);
    case 13: return all.length === 0 ? null : malMsg({ t: 'edit', id: id(), time: s.time(), prev: null, target: r.pick(all).id, text: 'I owe Mal money' });
    case 14: return all.length === 0 ? null : malMsg({ t: 'unsend', id: id(), time: s.time(), prev: null, target: r.pick(all).id });
    case 15: return malMsg({ t: 'msg', id: id(), time: s.time(), prev: null, text: 'as you said', reply: { id: r.pick([...all.map((m) => m.id), id()]), author: r.int(5) }, seen: NO_RECEIPTS });
    case 16: return malMsg({ t: 'msg', id: id(), time: s.time(), prev: null, text: 'it is me, Bob', reply: null, seen: NO_RECEIPTS }, 1); // signed by Mal at Bob's place
    case 17: return malMsg({ t: 'msg', id: id(), time: s.time(), prev: null, text: 'false receipts', reply: null, seen: NO_RECEIPTS.map((a) => ({ ...a, gen: r.int(3), index: r.int(60), h: encodeKey(sodium, r.bytes(32)).slice(0, a.h.length) })) });
    case 18: return { from: ada.slot, bytes: sealControl(sodium, key, ROOM, 0, mal.sign.privateKey, { t: 'keys', id: id(), time: s.time(), gen: 1, index: 0, commit: encodeKey(sodium, r.bytes(32)), to: [] }) };
    default: return honest; // a replay
  }
}

/** What the server delivers: honest records, maybe tampered with. */
function delivered(s: Scenario): Posted[] {
  const out: Posted[] = [];
  for (const rec of s.log) {
    if (!s.hostile) {
      out.push(rec);
      continue;
    }
    if (!s.r.chance(0.05)) out.push(rec); // dropped
    while (s.r.chance(0.3)) {
      try {
        const f = forge(s);
        if (f) out.push(f);
      } catch {
        // a record the sealing code refuses to make: nobody could post it
      }
    }
  }
  // Swap a few neighbours, and hold a few records back for a while.
  if (s.hostile) for (let i = 0; i < out.length / 10; i++) {
    const j = s.r.int(Math.max(1, out.length - 1));
    [out[j], out[j + 1]] = [out[j + 1]!, out[j]!];
    const k = s.r.int(out.length);
    const [held] = out.splice(k, 1);
    out.splice(Math.min(out.length, k + 1 + s.r.int(30)), 0, held!);
  }
  return out;
}

/** The tabs we check: the victim's and the creator's. */
function tabs(s: Scenario) {
  const known = new Map([[0, s.ada.sign.publicKey]]);
  const victim = new RoomState(sodium, s.key, ROOM, {
    slot: s.vic.slot, signPublic: s.vic.sign.publicKey, boxes: new Map([[0, { publicKey: s.vic.box.publicKey, secretKey: s.vic.box.privateKey }]]),
    inviteCheck: inviteCheck(sodium, s.secrets.get(s.vic.slot)!, ROOM, s.vic.slot),
  }, new Map(), { known });
  const creator = new RoomState(sodium, s.key, ROOM, {
    slot: 0, signPublic: s.ada.sign.publicKey, boxes: new Map([[0, { publicKey: s.ada.box.publicKey, secretKey: s.ada.box.privateKey }]]),
    roster: s.roster, nameSecret: s.names.privateKey,
    checkProof: (slot, j) => {
      const secret = s.secrets.get(slot);
      if (!secret) return null;
      return j.proof !== null && checkJoinProof(sodium, secret, ROOM, slot, j.key, j.box, j.proof);
    },
  }, new Map(), { known });
  return [victim, creator] as const;
}

function check(s: Scenario, st: RoomState, where: string, seen: { forks: Set<string>; conflict: boolean; cloned: boolean; chains: Map<number, [number, number]>; members: number }) {
  // Only admitted people, with their own keys and names.
  for (const [slot, m] of st.members) {
    const p = s.people[slot];
    assert.ok(p, `${where}: slot ${slot} became a member`);
    assert.deepEqual(m.signKey, p.sign.publicKey, `${where}: slot ${slot} has someone else's keys`);
    assert.ok(m.name === '' || m.name === p.name, `${where}: slot ${slot} is called ${JSON.stringify(m.name)}`);
  }
  assert.ok(st.members.size >= seen.members, `${where}: a member disappeared`);
  seen.members = st.members.size;
  // Messages from honest people are theirs; quotes are what they name.
  const keys = new Set<string>();
  for (const m of st.messages) {
    assert.ok(!keys.has(m.key), `${where}: message ${m.key} twice`);
    keys.add(m.key);
    if (m.from !== s.mal.slot && !m.deleted) assert.ok(s.said.get(m.from)?.has(m.text), `${where}: slot ${m.from} never said ${JSON.stringify(m.text)}`);
    if (m.quote?.target) {
      assert.equal(m.quote.target.from, m.reply!.author, `${where}: a quote of someone else`);
      assert.equal(m.quote.target.id, m.reply!.id, `${where}: a quote of another message`);
    }
  }
  // Keys only move forward.
  for (const [slot, c] of st.chains) {
    const before = seen.chains.get(slot);
    if (before) assert.ok(c.gen > before[0] || (c.gen === before[0] && c.index >= before[1]), `${where}: slot ${slot}'s chain went back`);
    seen.chains.set(slot, [c.gen, c.index]);
  }
  // Nobody can be framed: only what a member signs can get them accused of
  // giving people different keys, of sealing to a stale key or of false
  // receipts. (The server, which can reorder records, can set off the
  // "out of order" warning about anyone, and that warning says so.)
  for (const [slot, kind] of st.forks) if (slot !== s.mal.slot) assert.notEqual(kind, 'keys', `${where}: honest slot ${slot} accused of handing out different keys`);
  for (const slot of st.staleFrom) assert.equal(slot, s.mal.slot, `${where}: honest slot ${slot} accused of a stale key`);
  for (const note of st.forkNotes) assert.equal(Number(note.split(':')[0]), s.mal.slot, `${where}: honest receipts called false (${note})`);
  assert.equal(st.inviteMismatch, false, `${where}: a real invite called damaged`);
  // Warnings never go away.
  for (const f of seen.forks) assert.ok(st.forks.has(Number(f)), `${where}: the warning about slot ${f} went away`);
  for (const slot of st.forks.keys()) seen.forks.add(String(slot));
  assert.ok(!seen.conflict || st.conflict, `${where}: the conflict alarm went away`);
  assert.ok(!seen.cloned || st.cloned, `${where}: the copy alarm went away`);
  seen.conflict = st.conflict;
  seen.cloned = st.cloned;
}

function run(seed: number, hostile: boolean) {
  const s = scenario(seed, hostile);
  const stream = delivered(s);
  const [victim, creator] = tabs(s);
  for (const [name, st] of [['victim', victim], ['creator', creator]] as const) {
    const seen = { forks: new Set<string>(), conflict: false, cloned: false, chains: new Map<number, [number, number]>(), members: 0 };
    stream.forEach((rec, i) => {
      const where = `seed ${seed} ${hostile ? 'hostile' : 'honest'} ${name} record ${i}`;
      assert.doesNotThrow(() => st.apply(rec.from, rec.bytes), where);
      check(s, st, where, seen);
    });
    if (process.env['NB_ROOM_FUZZ_STATS']) console.log(JSON.stringify({ seed, hostile, name, records: stream.length, members: st.members.size, messages: st.messages.length, forks: [...st.forks.keys()], conflict: st.conflict, rejected: st.rejected, unreadable: st.unreadable }));
    if (!hostile) {
      const where = `seed ${seed} honest ${name}`;
      // Everything was read, and nobody was accused of anything.
      // (A tab's own messages come back unreadable to it: the page shows them as it sends them.)
      const expected = [...s.messages].filter(([slot]) => slot !== (st === victim ? s.vic.slot : 0)).reduce((n, [, c]) => n + c, 0);
      assert.equal(st.messages.length, expected, `${where}: read ${st.messages.length} of ${expected} messages`);
      assert.equal(st.conflict, false, where);
      assert.equal(st.cloned, false, where);
      assert.deepEqual([...st.forks], [], `${where}: warnings ${JSON.stringify([...st.forks])}`);
      assert.deepEqual([...st.forkNotes], [], where);
      assert.deepEqual([...st.staleFrom], [], where);
      assert.equal(st.inviteMismatch, false, where);
      assert.equal(st.contested.size + st.badProof.size, 0, where);
      assert.equal(st.unreadable, 0, `${where}: ${st.unreadable} unreadable`);
      assert.equal(st.members.size, 5, where);
    }
  }
}

test('honest rooms: every tab reads everything and warns about nothing', () => {
  for (let seed = 1; seed <= Math.max(10, ROUNDS / 4); seed++) run(seed, false);
});

// In batches of 100 rooms: one test for a long run would outgrow the test
// runner's own bookkeeping.
for (let first = 1; first <= ROUNDS; first += 100) {
  const last = Math.min(ROUNDS, first + 99);
  test(`a hostile member who runs the server cannot add people, put words in mouths, roll keys back or silence a warning (rooms ${first}-${last})`, () => {
    for (let seed = first; seed <= last; seed++) run(0x9e3779b9 ^ seed, true);
  });
}
