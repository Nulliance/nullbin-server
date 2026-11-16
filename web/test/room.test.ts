// Tests for Null Chat cryptography (web/src/room-crypto.ts) and the rules
// for trusting records (web/src/room-state.ts).

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { loadSodium } from '../src/sodium.ts';
import { paddedLength } from '../src/format.ts';
import { encodeInviteFragment, parseInviteFragment, parseKeyFragment } from '../src/link.ts';
import {
  MAX_MESSAGE_LENGTH,
  MAX_RECORD_BYTES,
  MAX_SKIP,
  REACTIONS,
  RECORD_MIN_PADDED,
  MESSAGE_MIN_PADDED,
  controlKey,
  encodeKey,
  newChain,
  advanceChain,
  newRecordId,
  boxKeyOk,
  checkOuterSignature,
  cleanText,
  signatureHash,
  outerSignature,
  NO_ACK,
  type Ack,
  boxName,
  sealName,
  sealRoster,
  chainCommit,
  contentHash,
  openBoxedName,
  openSealedName,
  openRoster,
  nameAllowed,
  openChainKey,
  openControl,
  openMessage,
  safetyCode,
  sealChainKey,
  sealControl,
  sealMessage,
  validControl,
  validMessage,
  verifySignature,
  type Chain,
  type ControlRecord,
  type MessageRecord,
} from '../src/room-crypto.ts';
import { RoomState, nameSkeleton, resembles } from '../src/room-state.ts';
import { MAX_BOX_N, checkJoinProof, inviteCheck, joinProof, roomPasswordKey } from '../src/room-crypto.ts';

const sodium = await loadSodium();
const ROOM = '0123456789abcdef0123456789abcdef';
const roomKey = sodium.randombytes_buf(32);
const key = controlKey(sodium, roomKey);
const enc = new TextEncoder();

interface Person { slot: number; sign: { publicKey: Uint8Array; privateKey: Uint8Array }; box: { publicKey: Uint8Array; privateKey: Uint8Array } }
const person = (slot: number): Person => ({ slot, sign: sodium.crypto_sign_keypair(), box: sodium.crypto_box_keypair() });
const id = () => newRecordId(sodium);
// The creator's roster key and name key, shared by every test room.
const ROSTER = sodium.randombytes_buf(32);
const NAMES = sodium.crypto_box_keypair();
/** A join: the creator's carries its name under the roster key and its name key; others', their name sealed to it. */
const join = (p: Person, name: string): ControlRecord => (p.slot === 0
  ? { t: 'join', id: id(), time: 1, name: boxName(sodium, ROSTER, name, ROOM, 'member', 0), key: encodeKey(sodium, p.sign.publicKey), box: encodeKey(sodium, p.box.publicKey), namekey: encodeKey(sodium, NAMES.publicKey) }
  : {
    t: 'join', id: id(), time: 1, key: encodeKey(sodium, p.sign.publicKey), box: encodeKey(sodium, p.box.publicKey),
    name: sealName(sodium, name, NAMES.publicKey, { roomId: ROOM, slot: p.slot, key: encodeKey(sodium, p.sign.publicKey), box: encodeKey(sodium, p.box.publicKey) }),
  });
const roomRec = (name: string, ends = 9, max = 20): ControlRecord => ({ t: 'room', id: id(), time: 1, name: boxName(sodium, ROSTER, name, ROOM, 'room', 0), ends, pw: false, max, ttl: 3600 });
const inviteRec = (slot: number, label: string, secret = sodium.randombytes_buf(32)): ControlRecord => ({ t: 'invite', id: id(), time: 1, slot, label: boxName(sodium, ROSTER, label, ROOM, 'label', slot), check: inviteCheck(sodium, secret, ROOM, slot), exp: 9 });
/** Receipts for every place: nothing read, except where given. */
const receipts = (...read: Ack[]): Ack[] => Array.from({ length: 20 }, (_, slot) => read.find((r) => r.slot === slot) ?? { slot, gen: 0, index: 0, h: NO_ACK });
const msg = (text: string): MessageRecord => ({ t: 'msg', id: id(), time: 2, text, reply: null, seen: receipts() });
const ctl = (p: Person, r: ControlRecord, slot = p.slot) => sealControl(sodium, key, ROOM, slot, p.sign.privateKey, r);
const copy = (c: Chain): Chain => ({ gen: c.gen, index: c.index, ck: c.ck.slice() });
const keysFor = (from: Person, chain: Chain, ...to: Person[]): ControlRecord =>
  ({
    t: 'keys', id: id(), time: 1, gen: chain.gen, index: chain.index, commit: chainCommit(sodium, chain.ck, { roomId: ROOM, slot: from.slot, gen: chain.gen, index: chain.index }),
    to: to.map((p) => ({ slot: p.slot, n: 0, box: sealChainKey(sodium, chain.ck, p.box.publicKey, { roomId: ROOM, slot: from.slot, gen: chain.gen, index: chain.index }, p.slot) })),
  });
/** A member's view; the creator's holds the roster key and name key from the start. */
const stateOf = (p: Person) => new RoomState(sodium, key, ROOM, {
  slot: p.slot, signPublic: p.sign.publicKey, boxes: new Map([[0, { publicKey: p.box.publicKey, secretKey: p.box.privateKey }]]),
  roster: p.slot === 0 ? ROSTER : null, nameSecret: p.slot === 0 ? NAMES.privateKey : null,
});
const admit = (p: Person, name = 'Someone'): ControlRecord => ({
  t: 'admit', id: id(), time: 1, slot: p.slot, key: encodeKey(sodium, p.sign.publicKey),
  roster: sealRoster(sodium, ROSTER, p.box.publicKey, ROOM, p.slot), name: boxName(sodium, ROSTER, name, ROOM, 'member', p.slot),
});
/** A member joins and the creator admits them. */
const enter = (s: RoomState, creator: Person, p: Person, name: string) => {
  s.apply(p.slot, ctl(p, join(p, name)));
  return s.apply(0, ctl(creator, admit(p, name)));
};

test('control records round-trip, bound to their key, room and slot', () => {
  const a = person(0);
  const r = join(a, 'Ada');
  const bytes = ctl(a, r);
  const opened = openControl(sodium, key, ROOM, 0, bytes);
  assert.ok(opened);
  assert.deepEqual(opened.record, r);
  assert.ok(verifySignature(sodium, opened, a.sign.publicKey));
  assert.ok(!verifySignature(sodium, opened, person(1).sign.publicKey));
  assert.equal(openControl(sodium, controlKey(sodium, sodium.randombytes_buf(32)), ROOM, 0, bytes), null, 'another room key');
  assert.equal(openControl(sodium, key, ROOM.replace('0', 'f'), 0, bytes), null, 'another room');
  assert.equal(openControl(sodium, key, ROOM, 1, bytes), null, 'stamped with another slot');
  for (let i = 0; i < bytes.length; i += 9) {
    const t = bytes.slice();
    t[i]! ^= 1;
    assert.equal(openControl(sodium, key, ROOM, 0, t), null, `flipped byte ${i}`);
  }
  assert.equal(openControl(sodium, key, ROOM, 0, bytes.subarray(0, bytes.length - 1)), null, 'truncated');
});

test('messages: one key each, deleted once used, so earlier messages cannot be read again', () => {
  const a = person(1);
  const sender = newChain(sodium, 1);
  const reader = copy(sender);
  const first = sealMessage(sodium, sender, ROOM, 1, a.sign.privateKey, msg('one'));
  const second = sealMessage(sodium, sender, ROOM, 1, a.sign.privateKey, msg('two'));
  assert.equal(sender.index, 2, 'the sender stepped past both keys');
  assert.equal(openMessage(sodium, reader, ROOM, 1, first, a.sign.publicKey)?.text, 'one');
  const afterFirst = reader.ck.slice();
  assert.equal(openMessage(sodium, reader, ROOM, 1, first, a.sign.publicKey), null, 'its key is gone: no second reading');
  assert.deepEqual(reader.ck, afterFirst, 'a failed read leaves the chain alone');
  assert.equal(openMessage(sodium, reader, ROOM, 1, second, a.sign.publicKey)?.text, 'two');
  // Someone who later steals the reader's current chain still cannot read either.
  const stolen = copy(reader);
  assert.equal(openMessage(sodium, stolen, ROOM, 1, first, a.sign.publicKey), null);
  assert.equal(openMessage(sodium, stolen, ROOM, 1, second, a.sign.publicKey), null);
});

test('messages: skipping ahead is bounded, and only an authentic message moves the chain', () => {
  const a = person(2);
  const insider = person(3); // holds a's chain key (any member does) but not a's signing key
  const sender = newChain(sodium, 4);
  const reader = copy(sender);
  const forger = copy(sender);
  const forged = sealMessage(sodium, forger, ROOM, 2, insider.sign.privateKey, msg('I am a'));
  const real = sealMessage(sodium, sender, ROOM, 2, a.sign.privateKey, msg('really a'));
  assert.equal(openMessage(sodium, reader, ROOM, 2, forged, a.sign.publicKey), null, 'wrong signer');
  assert.equal(reader.index, 0, 'the forgery did not consume the real message key');
  assert.equal(openMessage(sodium, reader, ROOM, 2, real, a.sign.publicKey)?.text, 'really a');
  // Another generation, another slot, too far ahead: refused.
  const later = newChain(sodium, 5);
  assert.equal(openMessage(sodium, reader, ROOM, 2, sealMessage(sodium, later, ROOM, 2, a.sign.privateKey, msg('gen 5')), a.sign.publicKey), null);
  const moved = copy(sender);
  assert.equal(openMessage(sodium, moved, ROOM, 3, sealMessage(sodium, copy(sender), ROOM, 2, a.sign.privateKey, msg('restamped')), a.sign.publicKey), null);
  const far = copy(sender);
  far.index += MAX_SKIP + 1;
  for (let i = 0; i < MAX_SKIP + 1; i++) sender.ck = sodium.crypto_kdf_derive_from_key(32, 1, 'nbrmnext', sender.ck);
  assert.equal(openMessage(sodium, copy({ ...reader }), ROOM, 2, sealMessage(sodium, far, ROOM, 2, a.sign.privateKey, msg('far')), a.sign.publicKey), null, 'more than MAX_SKIP ahead');
});

test('chain keys reach only the member they are sealed to', () => {
  const b = person(1);
  const c = person(2);
  const chain = newChain(sodium, 1);
  const place = { roomId: ROOM, slot: 0, gen: 1, index: 0 };
  const sealed = sealChainKey(sodium, chain.ck, b.box.publicKey, place, b.slot);
  assert.deepEqual(openChainKey(sodium, sealed, b.box.publicKey, b.box.privateKey, place, b.slot), chain.ck);
  assert.equal(openChainKey(sodium, sealed, b.box.publicKey, b.box.privateKey, place, c.slot), null, 'bound to its recipient');
  assert.equal(openChainKey(sodium, sealed, c.box.publicKey, c.box.privateKey, place, c.slot), null);
  assert.equal(openChainKey(sodium, sealed.slice(0, -2), b.box.publicKey, b.box.privateKey, place, b.slot), null);
  // Bound to its room, sender and position: it opens nowhere else.
  for (const other of [{ ...place, roomId: ROOM.replace('0', 'f') }, { ...place, slot: 2 }, { ...place, gen: 2 }, { ...place, index: 1 }]) {
    assert.equal(openChainKey(sodium, sealed, b.box.publicKey, b.box.privateKey, other, b.slot), null, JSON.stringify(other));
  }
});

test('short messages and control records have fixed sizes; the longest still fits', () => {
  const a = person(3);
  const chain = newChain(sodium, 1);
  const sizes = new Set<number>();
  for (const text of ['y', 'ok', 'x'.repeat(300), 'A longer message. '.repeat(40).slice(0, 600).trim()]) sizes.add(sealMessage(sodium, chain, ROOM, 3, a.sign.privateKey, msg(text)).length);
  assert.deepEqual([...sizes], [1 + 4 + 4 + 24 + 16 + MESSAGE_MIN_PADDED + 64], 'header, padded ciphertext, outer signature');
  // The largest JSON a valid message makes: three UTF-8 bytes per character.
  const big = sealMessage(sodium, chain, ROOM, 3, a.sign.privateKey, { ...msg('\u20AC'.repeat(MAX_MESSAGE_LENGTH)), reply: { id: id(), author: 19 } });
  assert.ok(big.length <= MAX_RECORD_BYTES, `${big.length}`);
  // A key delivery to 19 members fits too.
  const all = Array.from({ length: 19 }, (_, i) => person(i + 1));
  assert.ok(ctl(a, keysFor(a, chain, ...all)).length <= MAX_RECORD_BYTES);
});

function sealRaw(plain: Uint8Array, slot = 0): Uint8Array {
  const nonce = sodium.randombytes_buf(24);
  const ct = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(plain, enc.encode(`nullbin room v1 ${ROOM} ${slot}`), null, nonce, key);
  return new Uint8Array([1, ...nonce, ...ct]);
}
function layoutOf(json: Uint8Array, padTo: number, length = json.length, filler = 0): Uint8Array {
  const out = new Uint8Array(padTo).fill(filler);
  new DataView(out.buffer).setUint32(0, length);
  out.set(json.subarray(0, Math.min(json.length, Math.max(0, padTo - 4))), 4);
  out.fill(0, 4 + json.length, Math.min(padTo, 4 + json.length + 64));
  return out;
}

test('records must carry exactly their padding', () => {
  const json = enc.encode(JSON.stringify(join(person(0), 'Pad')));
  const canonical = paddedLength(4 + json.length + 64, RECORD_MIN_PADDED);
  assert.ok(openControl(sodium, key, ROOM, 0, sealRaw(layoutOf(json, canonical))), 'the canonical layout opens (signature unchecked)');
  for (const [label, plain] of [
    ['one byte short', layoutOf(json, canonical - 1)],
    ['one byte long', layoutOf(json, canonical + 1)],
    ['next size up', layoutOf(json, paddedLength(canonical + 1, RECORD_MIN_PADDED))],
    ['non-zero padding', layoutOf(json, canonical, json.length, 1)],
    ['length past the end', layoutOf(json, canonical, 0xffffffff)],
    ['length too short', layoutOf(json, canonical, json.length - 1)],
    ['no room for a signature', new Uint8Array(40)],
  ] as const) {
    assert.equal(openControl(sodium, key, ROOM, 0, sealRaw(plain)), null, label);
  }
});

test('every record type has an exact schema', () => {
  const p = person(0);
  const good: unknown[] = [
    roomRec(''), join(p, 'Ada'), { t: 'box', id: id(), time: 1, n: 1, box: encodeKey(sodium, sodium.randombytes_buf(32)) },
    inviteRec(19, ''), { t: 'remove', id: id(), time: 1, slot: 1 },
    keysFor(p, newChain(sodium, 1), person(1)), admit(person(3)),
  ];
  for (const r of good) assert.ok(validControl(r), JSON.stringify(r));
  assert.ok(validMessage(msg('hi')));
  assert.ok(validMessage({ ...msg('hi'), reply: { id: id(), author: 3 } }));
  const j = join(p, 'Ada');
  const k = keysFor(p, newChain(sodium, 1), person(1));
  for (const bad of [
    null, [], 'x', { ...j, extra: 1 }, { ...j, t: 'other' }, { ...j, id: 'xyz' }, { ...j, time: 0 }, { ...j, name: '' }, { ...j, name: ' Ada ' },
    { ...j, name: 'A\u202Eda' }, { ...j, key: 'short' }, { ...j, box: undefined }, inviteRec(0, ''),
    { t: 'remove', id: id(), time: 1, slot: 20 }, { t: 'room', id: id(), time: 1, name: 'Plain', ends: 9, pw: false, max: 20, ttl: 3600 }, { t: 'room', id: id(), time: 1, name: boxName(sodium, ROSTER, 'no end', ROOM, 'room', 0), pw: false, max: 20, ttl: 3600 },
    // Settings out of range, or missing.
    { ...roomRec('x'), max: 1 }, { ...roomRec('x'), max: 21 }, { ...roomRec('x'), max: 2.5 }, { ...roomRec('x'), ttl: 60 }, { ...roomRec('x'), pw: 1 },
    { t: 'room', id: id(), time: 1, name: boxName(sodium, ROSTER, 'no settings', ROOM, 'room', 0), ends: 9 },
    { ...inviteRec(1, 'Bo'), exp: 0 }, { ...inviteRec(1, 'Bo'), exp: 'soon' }, (({ exp: _, ...rest }) => rest)(inviteRec(1, 'Bo') as ControlRecord & { exp: number }),
    { ...k, gen: 0 }, { ...k, index: -1 }, { ...k, to: [] }, { ...k, to: [k.t === 'keys' ? k.to[0] : null, k.t === 'keys' ? k.to[0] : null] },
    { ...k, to: [{ slot: 1, n: 0, box: 'short' }] }, { ...k, to: [{ slot: 20, n: 0, box: k.t === 'keys' ? k.to[0]!.box : '' }] },
    { ...k, to: [{ slot: 1, box: k.t === 'keys' ? k.to[0]!.box : '' }] }, { ...k, to: [{ slot: 1, n: -1, box: k.t === 'keys' ? k.to[0]!.box : '' }] },
    { t: 'box', id: id(), time: 1, n: 0, box: encodeKey(sodium, sodium.randombytes_buf(32)) }, { t: 'box', id: id(), time: 1, n: 1, box: 'short' },
    Object.assign(Object.create({ polluted: true }), j), msg('hi'), { ...admit(person(0)) }, { ...admit(person(1)), key: 'short' },
  ]) {
    assert.ok(!validControl(bad), JSON.stringify(bad));
  }
  for (const bad of [{ ...msg('hi'), extra: 1 }, { ...msg(''), text: '' }, msg('x'.repeat(MAX_MESSAGE_LENGTH + 1)), { ...msg('hi'), reply: 'nope' }, { ...msg('hi'), reply: id() }, { ...msg('hi'), reply: { id: id() } }, { ...msg('hi'), reply: { id: id(), author: 20 } }, j]) {
    assert.ok(!validMessage(bad), JSON.stringify(bad));
  }
  assert.throws(() => sealControl(sodium, key, ROOM, 0, p.sign.privateKey, { ...j, extra: 1 } as unknown as ControlRecord));
});

test('the room state: signed joins fix each member’s keys; only the creator manages the room', () => {
  const a = person(0);
  const b = person(1);
  const mallory = person(2);
  const s = stateOf(a);
  assert.equal(s.apply(1, ctl(b, roomRec('too early'))), null, 'nothing before a join');
  assert.equal(s.apply(0, ctl(a, join(a, 'Ada')))?.kind, 'joined');
  assert.equal(s.apply(1, ctl(b, join(b, 'Bob')))?.kind, 'waiting', 'a join alone makes nobody a member');
  assert.equal(s.apply(1, ctl(b, admit(b))), null, 'only the creator admits');
  assert.equal(s.apply(0, ctl(a, admit(b)))?.kind, 'joined');
  assert.equal(s.apply(2, sealControl(sodium, key, ROOM, 2, b.sign.privateKey, join(mallory, 'Mal'))), null, 'a join not signed by its own key');
  assert.equal(s.apply(1, ctl(mallory, join(mallory, 'Bob'), 1)), null, 'a second join cannot replace keys');
  assert.deepEqual(s.members.get(1)!.signKey, b.sign.publicKey);
  for (const r of [roomRec('Mine'), inviteRec(3, 'x'), { t: 'remove', id: id(), time: 1, slot: 1 }, admit(mallory)] as ControlRecord[]) {
    assert.equal(s.apply(1, ctl(b, r)), null, `${r.t} from a member`);
  }
  assert.equal(s.apply(0, ctl(a, roomRec('Plans')))?.kind, 'renamed');
  assert.equal(s.apply(0, ctl(a, roomRec('Again'))), null, 'named once');
  assert.equal(s.name, 'Plans');
  const replay = ctl(a, inviteRec(4, 'Cleo'));
  assert.equal(s.apply(0, replay)?.kind, 'invited');
  assert.equal(s.apply(0, replay), null, 'replays show once');
  assert.equal(s.nameOf(4), 'Cleo');
  assert.equal(s.nameOf(9), 'Member 10');
});

test('the room state: messages need the sender’s chain, sealed to us; keys only move forward', () => {
  const a = person(0);
  const b = person(1);
  const c = person(2);
  const s = stateOf(b); // we are Bob
  s.apply(0, ctl(a, join(a, 'Ada')));
  enter(s, a, b, 'Bob');
  enter(s, a, c, 'Cleo');
  const ada = newChain(sodium, 1);
  // Sent before we had Ada's chain: unreadable, by design.
  assert.equal(s.apply(0, sealMessage(sodium, ada, ROOM, 0, a.sign.privateKey, msg('before'))), null);
  assert.equal(s.unreadable, 1);
  // Ada's keys, sealed to Cleo only, are no use to us.
  assert.equal(s.apply(0, ctl(a, keysFor(a, ada, c))), null);
  assert.equal(s.chains.size, 0);
  const delivery = ctl(a, keysFor(a, ada, c, b));
  assert.equal(s.apply(0, delivery)?.kind, 'keys');
  assert.equal(s.apply(0, sealMessage(sodium, ada, ROOM, 0, a.sign.privateKey, msg('hello')))?.kind, 'message');
  // Cleo has Ada's chain key too, but cannot post as Ada.
  const cleoForge = { gen: ada.gen, index: ada.index, ck: ada.ck.slice() };
  assert.equal(s.apply(0, sealMessage(sodium, cleoForge, ROOM, 0, c.sign.privateKey, msg('forged'))), null);
  assert.equal(s.apply(0, sealMessage(sodium, ada, ROOM, 0, a.sign.privateKey, msg('still Ada')))?.kind, 'message');
  // A replayed old delivery cannot move the chain back to deleted keys.
  const before = s.chains.get(0)!.index;
  assert.equal(s.apply(0, sealControl(sodium, key, ROOM, 0, a.sign.privateKey, keysFor(a, { gen: 1, index: 0, ck: sodium.randombytes_buf(32) }, b))), null);
  assert.equal(s.chains.get(0)!.index, before);
  // A new generation replaces it.
  const ada2 = newChain(sodium, 2);
  assert.equal(s.apply(0, ctl(a, keysFor(a, ada2, b)))?.kind, 'keys');
  assert.equal(s.apply(0, sealMessage(sodium, ada2, ROOM, 0, a.sign.privateKey, msg('fresh keys')))?.kind, 'message');
  // Our own messages come back unreadable to us and are skipped (the page shows them when sent).
  assert.equal(s.apply(1, sealMessage(sodium, newChain(sodium, 1), ROOM, 1, b.sign.privateKey, msg('mine'))), null);
  // Removal: their chain is deleted, and nothing more from them is accepted.
  const cleo = newChain(sodium, 1);
  s.apply(2, ctl(c, keysFor(c, cleo, b)));
  assert.ok(s.chains.has(2));
  assert.equal(s.apply(0, ctl(a, { t: 'remove', id: id(), time: 1, slot: 2 }))?.kind, 'removed');
  assert.ok(!s.chains.has(2));
  assert.equal(s.apply(2, sealMessage(sodium, cleo, ROOM, 2, c.sign.privateKey, msg('after removal'))), null);
  assert.equal(s.apply(2, ctl(c, keysFor(c, newChain(sodium, 2), b))), null);
  assert.deepEqual(s.messages.map((m) => m.text), ['hello', 'still Ada', 'fresh keys']);
  assert.deepEqual(s.recipients().map((m) => m.slot), [0]);
  s.wipe();
  assert.equal(s.chains.size, 0);
});

test('the room key alone reads no message', () => {
  // Someone with a leaked invite (the room key) and every stored record:
  // they see who is in the room, but not one message.
  const a = person(0);
  const b = person(1);
  const outsider = person(5);
  const s = stateOf(outsider);
  s.apply(0, ctl(a, join(a, 'Ada')));
  enter(s, a, b, 'Bob');
  const ada = newChain(sodium, 1);
  s.apply(0, ctl(a, keysFor(a, ada, b)));
  s.apply(0, sealMessage(sodium, ada, ROOM, 0, a.sign.privateKey, msg('secret')));
  assert.equal(s.messages.length, 0);
  assert.equal(s.members.size, 2);
});

test('safety codes are six groups of five digits, the same for everyone', () => {
  const k = sodium.randombytes_buf(32);
  const code = safetyCode(sodium, k);
  assert.match(code, /^\d{5} \d{5} \d{5} \d{5} \d{5} \d{5}$/);
  assert.equal(safetyCode(sodium, k.slice()), code);
  assert.notEqual(safetyCode(sodium, sodium.randombytes_buf(32)), code);
});

test('receiving keys rotate: deliveries sealed to a deleted key cannot be opened', () => {
  const a = person(0);
  const b = person(1);
  const s = stateOf(b);
  s.apply(0, ctl(a, join(a, 'Ada')));
  enter(s, a, b, 'Bob');
  // Bob announces receiving key 1; only Bob can, and numbers only go up.
  const next = sodium.crypto_box_keypair();
  const announce = (n: number, pk: Uint8Array, by = b): ControlRecord => ({ t: 'box', id: id(), time: 1, n, box: encodeKey(sodium, pk) });
  assert.equal(s.apply(1, sealControl(sodium, key, ROOM, 1, a.sign.privateKey, announce(1, next.publicKey))), null, 'not signed by Bob');
  assert.equal(s.apply(1, ctl(b, announce(1, next.publicKey)))?.kind, 'box');
  assert.equal(s.members.get(1)!.boxN, 1);
  assert.deepEqual(s.members.get(1)!.boxKey, next.publicKey);
  assert.equal(s.apply(1, ctl(b, announce(1, sodium.crypto_box_keypair().publicKey))), null, 'a number is used once');
  // A delivery sealed to key 0, recorded by the server: once Bob has deleted key 0, it opens for nobody.
  const ada = newChain(sodium, 1);
  const recorded = ctl(a, keysFor(a, ada, b));
  const later = new RoomState(sodium, key, ROOM, { slot: 1, signPublic: b.sign.publicKey, boxes: new Map([[1, { publicKey: next.publicKey, secretKey: next.privateKey }]]) });
  later.apply(0, ctl(a, join(a, 'Ada')));
  enter(later, a, b, 'Bob');
  assert.equal(later.apply(0, recorded), null);
  assert.equal(later.lostDeliveries, 1);
  assert.equal(later.chains.size, 0);
  // A delivery sealed to key 1 opens, and says which key it used.
  const c2 = newChain(sodium, 2);
  const fresh: ControlRecord = { t: 'keys', id: id(), time: 1, gen: 2, index: 0, commit: chainCommit(sodium, c2.ck, { roomId: ROOM, slot: 0, gen: 2, index: 0 }), to: [{ slot: 1, n: 1, box: sealChainKey(sodium, c2.ck, next.publicKey, { roomId: ROOM, slot: 0, gen: 2, index: 0 }, 1) }] };
  assert.deepEqual(later.apply(0, ctl(a, fresh)), { kind: 'keys', slot: 0, n: 1 });
  assert.equal(later.deliveredMax, 1, 'key 1 had a delivery: it is replaced next');
  // A delivery that does not move the chain still marks its key.
  const again = new RoomState(sodium, key, ROOM, { slot: 1, signPublic: b.sign.publicKey, boxes: new Map([[1, { publicKey: next.publicKey, secretKey: next.privateKey }]]) });
  again.apply(0, ctl(a, join(a, 'Ada')));
  enter(again, a, b, 'Bob');
  const chain = newChain(sodium, 3);
  again.apply(0, ctl(a, { t: 'keys', id: id(), time: 1, gen: 3, index: 5, commit: chainCommit(sodium, chain.ck, { roomId: ROOM, slot: 0, gen: 3, index: 5 }), to: [{ slot: 1, n: 1, box: sealChainKey(sodium, chain.ck, next.publicKey, { roomId: ROOM, slot: 0, gen: 3, index: 5 }, 1) }] }));
  again.deliveredMax = -1;
  assert.equal(again.apply(0, ctl(a, { t: 'keys', id: id(), time: 1, gen: 3, index: 2, commit: chainCommit(sodium, chain.ck, { roomId: ROOM, slot: 0, gen: 3, index: 2 }), to: [{ slot: 1, n: 1, box: sealChainKey(sodium, chain.ck, next.publicKey, { roomId: ROOM, slot: 0, gen: 3, index: 2 }, 1) }] })), null, 'an older position does not move the chain');
  assert.equal(again.deliveredMax, 1);
});

test('a joiner notices when the creator admitted someone else for their place', () => {
  const a = person(0);
  const b = person(1);
  const mallory = person(1); // a server working with someone who has the room key
  const s = stateOf(b);
  s.apply(0, ctl(a, join(a, 'Ada')));
  s.apply(1, ctl(mallory, join(mallory, 'Bob')));
  assert.equal(s.impostor(), false, 'a join alone takes no place');
  s.apply(1, ctl(b, join(b, 'Bob')));
  assert.ok(s.waitingForAdmit());
  s.apply(0, ctl(a, admit(mallory)));
  assert.equal(s.impostor(), true);
  assert.equal(s.members.has(1), true);
  assert.deepEqual(s.members.get(1)!.signKey, mallory.sign.publicKey);
  const honest = stateOf(b);
  honest.apply(0, ctl(a, join(a, 'Ada')));
  enter(honest, a, b, 'Bob');
  assert.equal(honest.impostor(), false);
});

test('the room key alone, even with the server, adds no member', () => {
  // Someone with any invite link (the room key), working with the server,
  // posts a join for a place nobody was invited to, or for a used invite.
  const a = person(0);
  const b = person(1);
  const eve = person(7);
  const eveAsBob = person(1);
  const s = stateOf(a);
  s.apply(0, ctl(a, join(a, 'Ada')));
  s.apply(0, ctl(a, inviteRec(1, 'Bob')));
  enter(s, a, b, 'Bob');
  assert.equal(s.apply(7, ctl(eve, join(eve, 'Eve')))?.kind, 'waiting');
  assert.equal(s.apply(1, ctl(eveAsBob, join(eveAsBob, 'Bob'))), null, 'a used place');
  assert.deepEqual(s.recipients().map((m) => m.slot), [1], 'keys go only to admitted members');
  assert.equal(s.joinsToAdmit().size, 0, 'the creator admits only invited places');
  // A second admit for a place, with other keys: someone is showing members different rooms.
  s.apply(0, ctl(a, admit(eveAsBob)));
  assert.equal(s.conflict, true);
  // A forged creator: the joiner's link pins the real creator's key.
  const fake = person(0);
  const pinned = new RoomState(sodium, key, ROOM, { slot: 1, signPublic: b.sign.publicKey, boxes: new Map() }, new Map(), { known: new Map([[0, a.sign.publicKey]]) });
  assert.equal(pinned.apply(0, ctl(fake, join(fake, 'Ada'))), null);
  assert.equal(pinned.conflict, true);
});

test('joins prove they come from the place’s invite link', () => {
  const a = person(0);
  const b = person(1);
  const mallory = person(1); // has the room key (another link), not Bob's invite secret
  const secret = sodium.randombytes_buf(32);
  const withProof = (p: Person, s: Uint8Array): ControlRecord => {
    const j = join(p, 'Bob') as ControlRecord & { t: 'join' };
    return { ...j, proof: joinProof(sodium, s, ROOM, p.slot, j.key, j.box) };
  };
  const real = withProof(b, secret) as ControlRecord & { t: 'join' };
  const fake = withProof(mallory, sodium.randombytes_buf(32)) as ControlRecord & { t: 'join' };
  assert.ok(validControl(real));
  assert.ok(checkJoinProof(sodium, secret, ROOM, 1, real.key, real.box, real.proof!));
  assert.ok(!checkJoinProof(sodium, secret, ROOM, 1, fake.key, fake.box, fake.proof!), 'another secret');
  assert.ok(!checkJoinProof(sodium, secret, ROOM, 2, real.key, real.box, real.proof!), 'another place');
  assert.ok(!checkJoinProof(sodium, secret, ROOM, 1, fake.key, real.box, real.proof!), 'other keys');
  assert.ok(!checkJoinProof(sodium, secret, ROOM.replace('0', 'f'), 1, real.key, real.box, real.proof!), 'another room');
  // The creator's state lists both joins for the invited place, in order:
  // its app admits the first one whose proof checks.
  const s = stateOf(a);
  s.apply(0, ctl(a, join(a, 'Ada')));
  s.apply(0, ctl(a, inviteRec(1, 'Bob')));
  s.apply(1, ctl(mallory, fake));
  s.apply(1, ctl(b, real));
  const waiting = s.joinsToAdmit().get(1)!;
  assert.equal(waiting.length, 2);
  const pick = waiting.find((m) => m.join.proof !== null && checkJoinProof(sodium, secret, ROOM, 1, m.join.key, m.join.box, m.join.proof));
  assert.deepEqual(pick?.signKey, b.sign.publicKey);
});

test('in a chat with a password, a join must prove the link and the password together', () => {
  const b = person(1);
  const secret = sodium.randombytes_buf(32);
  const right = roomPasswordKey(sodium, 'correct horse battery', ROOM);
  assert.equal(right.length, 32);
  assert.deepEqual(roomPasswordKey(sodium, 'correct horse battery', ROOM), right, 'the same password gives the same key in one room');
  assert.notDeepEqual(roomPasswordKey(sodium, 'correct horse battery', ROOM.replace('0', 'f')), right, 'salted by the room');
  assert.deepEqual(roomPasswordKey(sodium, 'café password', ROOM), roomPasswordKey(sodium, 'café password', ROOM), 'NFC first');
  const wrong = roomPasswordKey(sodium, 'correct horse batterz', ROOM);
  assert.throws(() => roomPasswordKey(sodium, '', ROOM));
  assert.throws(() => roomPasswordKey(sodium, 'x'.repeat(1025), ROOM));
  const k = encodeKey(sodium, b.sign.publicKey);
  const box = encodeKey(sodium, b.box.publicKey);
  const withPw = joinProof(sodium, secret, ROOM, 1, k, box, right);
  const without = joinProof(sodium, secret, ROOM, 1, k, box);
  assert.ok(checkJoinProof(sodium, secret, ROOM, 1, k, box, withPw, right));
  assert.ok(!checkJoinProof(sodium, secret, ROOM, 1, k, box, withPw, wrong), 'a wrong password');
  assert.ok(!checkJoinProof(sodium, secret, ROOM, 1, k, box, without, right), 'the link alone');
  assert.ok(!checkJoinProof(sodium, secret, ROOM, 1, k, box, withPw), 'a password proof is not a link-only proof');
  assert.ok(!checkJoinProof(sodium, sodium.randombytes_buf(32), ROOM, 1, k, box, withPw, right), 'the password alone');
  assert.ok(!checkJoinProof(sodium, secret, ROOM, 2, k, box, withPw, right), 'another place');
  assert.throws(() => joinProof(sodium, secret, ROOM, 1, k, box, right.subarray(1)));
});

test('members refuse admits past the chat’s signed member limit', () => {
  const a = person(0);
  const b = person(1);
  const c = person(2);
  const d = person(3);
  const s = stateOf(person(4));
  s.apply(0, ctl(a, join(a, 'Ada')));
  s.apply(0, ctl(a, roomRec('Pair', 9, 2)));
  assert.equal(s.maxMembers, 2);
  assert.equal(enter(s, a, b, 'Bo')?.kind, 'joined');
  assert.equal(s.activeCount(), 2);
  // A third person in a chat for two: refused, whoever signed it.
  assert.equal(enter(s, a, c, 'Cy'), null);
  assert.ok(s.overLimit.has(2));
  assert.ok(!s.members.has(2));
  // A removal frees the place.
  s.apply(0, ctl(a, { t: 'remove', id: id(), time: 1, slot: 1 }));
  assert.equal(s.activeCount(), 1);
  assert.equal(enter(s, a, d, 'Di')?.kind, 'joined');
});

test('the creator’s signed settings and invite expiry are read', () => {
  const a = person(0);
  const s = stateOf(person(4));
  s.apply(0, ctl(a, join(a, 'Ada')));
  s.apply(0, ctl(a, { t: 'room', id: id(), time: 1, name: boxName(sodium, ROSTER, 'Set', ROOM, 'room', 0), ends: 9, pw: true, max: 5, ttl: 300 }));
  assert.deepEqual([s.passwordRequired, s.maxMembers, s.inviteTtl], [true, 5, 300]);
  // Only the first room record counts.
  s.apply(0, ctl(a, { t: 'room', id: id(), time: 1, name: boxName(sodium, ROSTER, 'Set', ROOM, 'room', 0), ends: 9, pw: false, max: 20, ttl: 3600 }));
  assert.deepEqual([s.passwordRequired, s.maxMembers, s.inviteTtl], [true, 5, 300]);
  s.apply(0, ctl(a, { ...inviteRec(1, 'Bo'), exp: 1234 } as ControlRecord));
  assert.equal(s.inviteExpires.get(1), 1234);
});

test('a reload cannot be shown a different history than before', () => {
  const a = person(0);
  const b = person(1);
  const other = person(1);
  const known = new Map([[0, a.sign.publicKey], [1, b.sign.publicKey]]);
  const s = new RoomState(sodium, key, ROOM, { slot: 0, signPublic: a.sign.publicKey, boxes: new Map() }, new Map(), { known, removed: [2] });
  s.apply(0, ctl(a, join(a, 'Ada')));
  assert.equal(s.apply(1, ctl(other, join(other, 'Bob'))), null, 'other keys for a known place');
  assert.equal(s.conflict, false, 'a stray join is refused, not an alarm');
  assert.equal(s.apply(0, ctl(a, admit(other))), null);
  assert.equal(s.conflict, true, 'a second admit for a known place is tampering');
  const t = new RoomState(sodium, key, ROOM, { slot: 0, signPublic: a.sign.publicKey, boxes: new Map() }, new Map(), { known, removed: [2] });
  t.apply(0, ctl(a, join(a, 'Ada')));
  assert.equal(t.apply(1, ctl(b, join(b, 'Bob')))?.kind, 'joined', 'a known member needs no new admit');
  assert.equal(t.conflict, false);
  const c = person(2);
  assert.equal(t.apply(2, ctl(c, join(c, 'Cleo'))), null, 'a removal stays, even if the history leaves it out');
  assert.ok(t.removed.has(2));
});

test('members with the same name are told apart', () => {
  const a = person(0);
  const b = person(1);
  const s = stateOf(a);
  s.apply(0, ctl(a, join(a, 'Sam')));
  assert.equal(s.nameOf(0), 'Sam');
  enter(s, a, b, 'Sam');
  assert.match(s.nameOf(0), /^Sam \(\d{5} \d{5} \d{5}\)$/);
  assert.notEqual(s.nameOf(0), s.nameOf(1));
});

test('nobody else can appear as "You", and names differing only in case are told apart', () => {
  const a = person(0);
  const b = person(1);
  const c = person(2);
  const s = stateOf(a);
  s.apply(0, ctl(a, join(a, 'Ada')));
  enter(s, a, b, 'you');
  assert.match(s.nameOf(1), /^you \(\d{5} \d{5} \d{5}\)$/);
  enter(s, a, c, 'ADA');
  assert.match(s.nameOf(0), /^Ada \(\d{5} \d{5} \d{5}\)$/);
  assert.match(s.nameOf(2), /^ADA \(\d{5} \d{5} \d{5}\)$/);
});

test('names that only look alike are told apart', () => {
  // Invisible joiners, other scripts' letters, combining marks, other
  // Unicode forms: they all look like the same name.
  for (const [real, fake] of [['Ada', 'Ada\u200D'], ['Ada', '\u0410da'], ['Alice', 'Ali\u0441e'], ['Zoe', 'Zo\u0065\u0301'], ['You', 'Y\u043Eu'], ['Ada', 'A da']]) {
    assert.equal(nameSkeleton(real!), nameSkeleton(fake!), `${real} / ${JSON.stringify(fake)}`);
  }
  assert.notEqual(nameSkeleton('Ada'), nameSkeleton('Adam'));
  const a = person(0);
  const b = person(1);
  const c = person(2);
  const d = person(3);
  const s = stateOf(a);
  s.apply(0, ctl(a, join(a, 'Ada')));
  enter(s, a, b, 'Ada\u200D');
  assert.match(s.nameOf(0), /^Ada \(\d{5} \d{5} \d{5}\)$/);
  assert.match(s.nameOf(1), /\(\d{5} \d{5} \d{5}\)$/);
  enter(s, a, c, 'Y\u043Eu');
  assert.match(s.nameOf(2), /\(\d{5} \d{5} \d{5}\)$/, 'a lookalike "You"');
  enter(s, a, d, 'Ada (you)');
  assert.match(s.nameOf(3), /\(\d{5} \d{5} \d{5}\)$/, '"you" anywhere in a name');
});

test('invite links: the room key stays in the fragment and the format is strict', () => {
  const token = sodium.to_base64(sodium.randombytes_buf(32), sodium.base64_variants.URLSAFE_NO_PADDING);
  const creator = sodium.randombytes_buf(32);
  const secret = sodium.randombytes_buf(32);
  const f = encodeInviteFragment(sodium, roomKey, token, creator, secret, 3);
  assert.ok(f.endsWith('.n3'));
  assert.deepEqual(parseInviteFragment(sodium, `#${f}`), { key: roomKey, invite: token, creator, secret, slot: 3, password: false });
  // A chat with a password: the link says so, as a hint for the page.
  const fp = encodeInviteFragment(sodium, roomKey, token, creator, secret, 3, true);
  assert.ok(fp.endsWith('.n3.p'));
  assert.deepEqual(parseInviteFragment(sodium, `#${fp}`), { key: roomKey, invite: token, creator, secret, slot: 3, password: true });
  for (const bad of [`${fp}.p`, `${fp}x`, fp.replace('.p', '.P'), fp.replace('.p', '.'), `${f}.q`]) assert.equal(parseInviteFragment(sodium, bad), null, bad);
  for (const bad of ['', '#', f.slice(1), `${f}A`, f.replace('.i', '.x'), f.replace('.c', '.d'), f.replace('.s', '.t'), `${f}.i${token}`, f.replace(/^./, '+'), f.slice(0, f.indexOf('.c')), f.slice(0, f.indexOf('.s')),
    f.slice(0, f.indexOf('.n')), f.replace('.n3', '.n0'), f.replace('.n3', '.n20'), f.replace('.n3', '.n03'), f.replace('.n3', '.n')]) {
    assert.equal(parseInviteFragment(sodium, bad), null, bad);
  }
  assert.equal(parseKeyFragment(sodium, f), null, 'never mistaken for a paste link');
  assert.equal(parseInviteFragment(sodium, sodium.to_base64(roomKey, sodium.base64_variants.URLSAFE_NO_PADDING)), null);
  assert.throws(() => encodeInviteFragment(sodium, roomKey.subarray(1), token, creator, secret, 3));
  assert.throws(() => encodeInviteFragment(sodium, roomKey, 'short', creator, secret, 3));
  assert.throws(() => encodeInviteFragment(sodium, roomKey, token, creator.subarray(1), secret, 3));
  assert.throws(() => encodeInviteFragment(sodium, roomKey, token, creator, secret.subarray(1), 3));
  for (const slot of [0, 20, 1.5]) assert.throws(() => encodeInviteFragment(sodium, roomKey, token, creator, secret, slot));
});

test('chat rules: only the sender edits or unsends; reactions toggle once per person', () => {
  const a = person(0);
  const b = person(1);
  const s = stateOf(b);
  s.apply(0, ctl(a, join(a, 'Ada')));
  s.apply(1, ctl(b, join(b, 'Bob')));
  const ada = newChain(sodium, 1);
  s.apply(0, ctl(a, keysFor(a, ada, b)));
  const fromAda = (r: MessageRecord) => s.apply(0, sealMessage(sodium, ada, ROOM, 0, a.sign.privateKey, r));
  const hello = msg('hello');
  assert.equal(fromAda(hello)?.kind, 'message');
  // Bob (us) cannot edit or unsend Ada's message, even locally.
  assert.equal(s.applyOwn({ t: 'edit', id: id(), time: 3, target: hello.id, text: 'changed by Bob' }), null);
  assert.equal(s.applyOwn({ t: 'unsend', id: id(), time: 3, target: hello.id }), null);
  assert.equal(s.message(`0:${hello.id}`)!.text, 'hello');
  // Ada edits it: the text changes and it is marked edited.
  assert.equal(fromAda({ t: 'edit', id: id(), time: 3, target: hello.id, text: 'hello all' })?.kind, 'updated');
  assert.equal(s.message(`0:${hello.id}`)!.text, 'hello all');
  assert.ok(s.message(`0:${hello.id}`)!.edited);
  // Reactions: one per person per emoji, and they can be taken back.
  const [thumbs, heart] = REACTIONS;
  assert.equal(s.applyOwn({ t: 'react', id: id(), time: 4, target: hello.id, author: 0, emoji: thumbs!, on: true })?.kind, 'updated');
  assert.equal(s.applyOwn({ t: 'react', id: id(), time: 4, target: hello.id, author: 0, emoji: thumbs!, on: true }), null, 'twice is once');
  assert.equal(fromAda({ t: 'react', id: id(), time: 4, target: hello.id, author: 0, emoji: thumbs!, on: true })?.kind, 'updated');
  assert.deepEqual([...s.message(`0:${hello.id}`)!.reactions.get(thumbs!)!].sort(), [0, 1]);
  assert.equal(s.applyOwn({ t: 'react', id: id(), time: 5, target: hello.id, author: 0, emoji: thumbs!, on: false })?.kind, 'updated');
  assert.deepEqual([...s.message(`0:${hello.id}`)!.reactions.get(thumbs!)!], [0]);
  assert.equal(s.applyOwn({ t: 'react', id: id(), time: 5, target: hello.id, author: 0, emoji: heart!, on: false }), null, 'nothing to take back');
  // Records about a message we do not have change nothing.
  assert.equal(fromAda({ t: 'edit', id: id(), time: 6, target: id(), text: 'ghost' }), null);
  // Unsent: the text is gone, and it can no longer be edited or reacted to.
  assert.equal(fromAda({ t: 'unsend', id: id(), time: 7, target: hello.id })?.kind, 'updated');
  const gone = s.message(`0:${hello.id}`)!;
  assert.ok(gone.deleted);
  assert.equal(gone.text, '');
  assert.equal(gone.reactions.size, 0);
  assert.equal(fromAda({ t: 'edit', id: id(), time: 8, target: hello.id, text: 'back' }), null);
  assert.equal(s.applyOwn({ t: 'react', id: id(), time: 8, target: hello.id, author: 0, emoji: thumbs!, on: true }), null);
  // Replies keep the message they reply to, and its sender.
  const reply: MessageRecord = { t: 'msg', id: id(), time: 9, text: 'answer', reply: { id: hello.id, author: 0 }, seen: receipts() };
  assert.equal(s.applyOwn(reply)?.kind, 'message');
  assert.deepEqual(s.message(`1:${reply.id}`)!.reply, { id: hello.id, author: 0 });
});

test('chat record schemas: reactions only from the fixed set, edits within the limit', () => {
  const target = id();
  for (const good of [
    { t: 'react', id: id(), time: 1, target, author: 2, emoji: REACTIONS[0], on: true },
    { t: 'edit', id: id(), time: 1, target, text: 'x' },
    { t: 'unsend', id: id(), time: 1, target },
  ]) assert.ok(validMessage(good), JSON.stringify(good));
  for (const bad of [
    { t: 'react', id: id(), time: 1, target, emoji: REACTIONS[0], on: true },
    { t: 'react', id: id(), time: 1, target, author: 20, emoji: REACTIONS[0], on: true },
    { t: 'react', id: id(), time: 1, target, emoji: 'x', on: true },
    { t: 'react', id: id(), time: 1, target, emoji: '<b>', on: true },
    { t: 'react', id: id(), time: 1, target, emoji: REACTIONS[0], on: 'yes' },
    { t: 'react', id: id(), time: 1, target: 'nope', emoji: REACTIONS[0], on: true },
    { t: 'edit', id: id(), time: 1, target, text: '' },
    { t: 'edit', id: id(), time: 1, target, text: 'x'.repeat(MAX_MESSAGE_LENGTH + 1) },
    { t: 'unsend', id: id(), time: 1, target, extra: 1 },
    { t: 'delete', id: id(), time: 1, target },
  ]) assert.ok(!validMessage(bad), JSON.stringify(bad));
});

test('a member cannot pass off a chain key sealed by someone else as theirs', () => {
  const a = person(0);
  const b = person(1);
  const m = person(2);
  const s = stateOf(b);
  s.apply(0, ctl(a, join(a, 'Ada')));
  enter(s, a, b, 'Bob');
  enter(s, a, m, 'Mal');
  const ada = newChain(sodium, 1);
  const delivery = keysFor(a, ada, b);
  // Mallory copies Ada's sealed key for Bob into a delivery of her own.
  const before = s.rejected;
  assert.equal(s.apply(2, ctl(m, { ...delivery, id: id() })), null);
  assert.equal(s.chains.has(2), false);
  assert.equal(s.rejected, before + 1);
  assert.deepEqual(s.apply(0, ctl(a, delivery)), { kind: 'keys', slot: 0, n: 0 });
});

test('low-order receiving keys are refused, so one member cannot stop everyone’s key deliveries', () => {
  assert.ok(boxKeyOk(sodium, sodium.crypto_box_keypair().publicKey));
  const zero = new Uint8Array(32);
  const one = new Uint8Array(32);
  one[0] = 1;
  for (const bad of [zero, one, new Uint8Array(31)]) assert.ok(!boxKeyOk(sodium, bad));
  const a = person(0);
  const b = person(1);
  const s = stateOf(a);
  s.apply(0, ctl(a, join(a, 'Ada')));
  assert.equal(s.apply(1, ctl(b, { ...join(b, 'Bob'), box: encodeKey(sodium, zero) })), null, 'a join with a low-order key');
  enter(s, a, b, 'Bob');
  assert.equal(s.apply(1, ctl(b, { t: 'box', id: id(), time: 1, n: 1, box: encodeKey(sodium, zero) })), null, 'a new low-order key');
  assert.equal(s.members.get(1)!.boxN, 0);
});

test('replies and reactions name the sender, so reusing an id cannot stand in for someone else’s message', () => {
  const a = person(0);
  const b = person(1);
  const m = person(2);
  const s = stateOf(b);
  s.apply(0, ctl(a, join(a, 'Ada')));
  enter(s, a, b, 'Bob');
  enter(s, a, m, 'Mal');
  const ada = newChain(sodium, 1);
  const mal = newChain(sodium, 1);
  s.apply(0, ctl(a, keysFor(a, ada, b)));
  s.apply(2, ctl(m, keysFor(m, mal, b)));
  const x = id(); // a message of Ada's that Bob never had
  assert.equal(s.apply(2, sealMessage(sodium, mal, ROOM, 2, m.sign.privateKey, { t: 'msg', id: x, time: 2, text: 'Send the deposit to me', reply: null, seen: receipts() }))?.kind, 'message');
  const e = s.apply(0, sealMessage(sodium, ada, ROOM, 0, a.sign.privateKey, { t: 'msg', id: id(), time: 3, text: 'Yes, do it', reply: { id: x, author: 0 }, seen: receipts() }));
  const reply = e?.kind === 'message' ? e.message : null;
  assert.ok(reply);
  assert.deepEqual({ author: reply.quote!.author, text: reply.quote!.text, target: reply.quote!.target }, { author: 0, text: null, target: null }, 'quotes Ada’s unknown message, not Mallory’s');
  assert.equal(s.apply(0, sealMessage(sodium, ada, ROOM, 0, a.sign.privateKey, { t: 'react', id: id(), time: 4, target: x, author: 0, emoji: REACTIONS[0]!, on: true })), null);
  assert.equal(s.message(`2:${x}`)!.reactions.size, 0, 'a reaction to Ada’s message does not land on Mallory’s');
});

test('a quote keeps the text replied to; the message itself shows the edit', () => {
  const a = person(0);
  const b = person(1);
  const s = stateOf(b);
  s.apply(0, ctl(a, join(a, 'Ada')));
  enter(s, a, b, 'Bob');
  const ada = newChain(sodium, 1);
  s.apply(0, ctl(a, keysFor(a, ada, b)));
  const meet = msg('Meet at 6');
  s.apply(0, sealMessage(sodium, ada, ROOM, 0, a.sign.privateKey, meet));
  const e = s.applyOwn({ t: 'msg', id: id(), time: 3, text: 'Agreed', reply: { id: meet.id, author: 0 }, seen: receipts() });
  const reply = e?.kind === 'message' ? e.message : null;
  assert.equal(reply!.quote!.text, 'Meet at 6');
  s.apply(0, sealMessage(sodium, ada, ROOM, 0, a.sign.privateKey, { t: 'edit', id: id(), time: 4, target: meet.id, text: 'Share the room with my friend' }));
  assert.equal(reply!.quote!.text, 'Meet at 6');
  assert.equal(reply!.quote!.target!.text, 'Share the room with my friend');
});

test('message text cannot hide direction changes, control characters or stacks of marks', () => {
  for (const bad of ['\u202E4321', 'a\u2066b', 'a\u200Fb', 'a\u0007', '\nx', 'x ', '   ', 'e' + '\u0301'.repeat(6), 'a\n\n\n\nb']) {
    assert.ok(!validMessage(msg(bad)), JSON.stringify(bad));
  }
  for (const good of ['line one\nline two', 'tab\there', 'e\u0301', '\u{1F469}\u200D\u{1F4BB}', 'a\n\n\nb']) assert.ok(validMessage(msg(good)), JSON.stringify(good));
  assert.equal(cleanText(' \u202E4321\u202C \r\n'), ' 4321', 'the indent stays');
  assert.equal(cleanText('e' + '\u0301'.repeat(9)), 'e' + '\u0301'.repeat(5));
  assert.equal(cleanText('a\r\n\n\n\n\nb'), 'a\n\n\nb');
  for (const t of ['\u202E4321', 'e' + '\u0301'.repeat(9), 'a\n\n\n\n\nb', ' x\r\n']) assert.ok(validMessage(msg(cleanText(t))), JSON.stringify(t));
});

test('names cannot carry a fake code or stacks of marks, and more lookalikes count as the same', () => {
  for (const bad of ['Bob (12345)', 'Bob [1]', 'Bob (code 12345)', 'Bob \uFF0812345\uFF09', 'Sam \u300C12345\u300D', 'Sam \u27E812345 67890\u27E9', 'Sam \u301412345\u3015', 'Sam \u2E2812345\u2E29', 'Sam <12345>', 'Z\u0301\u0301\u0301\u0301']) assert.ok(!nameAllowed(bad), bad);
  for (const good of ['Bob', 'Bob (work)', 'Agent 47', 'Zo\u00EB', 'Jos\u00E9']) assert.ok(nameAllowed(good), good);
  assert.ok(!validControl({ ...join(person(1), 'x'), name: 'Bob (12345)' }));
  for (const [a, b] of [['Alice', 'AIice'], ['Sam', 'Sarn'], ['Bob', 'Bob.'], ['William', 'WiIliam'], ['Ian', 'ian'], ['You', '\uA4ECou']]) {
    assert.equal(nameSkeleton(a!) === nameSkeleton(b!) || a === 'You', true, `${a} / ${b}`);
  }
});

test('a name like another invite’s gets a tag, and everyone sees whose invite was used', () => {
  const a = person(0);
  const b = person(1);
  const c = person(2);
  const d = person(3);
  const s = stateOf(a);
  s.apply(0, ctl(a, join(a, 'Ada')));
  s.apply(0, ctl(a, inviteRec(1, 'Alex')));
  s.apply(0, ctl(a, inviteRec(2, 'Mallory')));
  enter(s, a, c, 'Alex');
  assert.match(s.nameOf(2), /^Alex \(\d{5} \d{5} \d{5}\)$/, 'the name of someone else’s invite');
  assert.equal(s.invitedAs(2), 'Mallory');
  enter(s, a, b, 'alex');
  assert.equal(s.invitedAs(1), null);
  // A lookalike in a script the app does not fold still mixes scripts.
  enter(s, a, d, '\uA4ECou');
  assert.match(s.nameOf(3), /\(\d{5} \d{5} \d{5}\)$/);
});

test('records made with our keys that this tab never posted mean another copy is using them; the server cannot fake one', () => {
  const a = person(0);
  const b = person(1);
  const posted = new Set<string>();
  const boxes = new Map([[0, { publicKey: b.box.publicKey, secretKey: b.box.privateKey }]]);
  const s = new RoomState(sodium, key, ROOM, { slot: 1, signPublic: b.sign.publicKey, boxes, posted: (h) => posted.has(h) });
  s.apply(0, ctl(a, join(a, 'Ada')));
  enter(s, a, b, 'Bob');
  const ours = (bytes: Uint8Array) => {
    posted.add(signatureHash(sodium, bytes[0] === 2 ? outerSignature(bytes) : openControl(sodium, key, ROOM, 1, bytes)!.signature));
    return bytes;
  };
  const chain = newChain(sodium, 1);
  const sent = ours(sealMessage(sodium, chain, ROOM, 1, b.sign.privateKey, msg('ours')));
  assert.ok(checkOuterSignature(sodium, b.sign.publicKey, ROOM, 1, sent));
  assert.ok(!checkOuterSignature(sodium, a.sign.publicKey, ROOM, 1, sent), 'signed by Bob only');
  assert.ok(!checkOuterSignature(sodium, b.sign.publicKey, ROOM, 2, sent), 'for his place only');
  s.apply(1, sent);
  s.apply(1, ours(ctl(b, { t: 'box', id: id(), time: 1, n: 1, box: encodeKey(sodium, sodium.crypto_box_keypair().publicKey) })));
  assert.equal(s.cloned, false, 'what we posted comes back');
  // Re-encrypting one of our records, which anyone with the room key can,
  // keeps its signature: no alarm.
  const box2 = ours(ctl(b, { t: 'box', id: id(), time: 1, n: 2, box: encodeKey(sodium, sodium.crypto_box_keypair().publicKey) }));
  const plain = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, box2.subarray(25), enc.encode(`nullbin room v1 ${ROOM} 1`), box2.subarray(1, 25), key);
  s.apply(1, sealRaw(plain, 1));
  assert.equal(s.cloned, false, 'one of our records, encrypted again');
  // The server can change a message's unauthenticated parts, but not sign
  // it again: no alarm.
  const forged = sent.slice();
  new DataView(forged.buffer).setUint32(5, 50);
  s.apply(1, forged);
  assert.equal(s.cloned, false, 'a message the server changed');
  // A copy of our keys sealing a message, even at a place behind ours.
  s.apply(1, sealMessage(sodium, newChain(sodium, 1), ROOM, 1, b.sign.privateKey, msg('a copy')));
  assert.ok(s.cloned, 'a message with our tag that we never posted');
  const t = new RoomState(sodium, key, ROOM, { slot: 1, signPublic: b.sign.publicKey, boxes, posted: (h) => posted.has(h) });
  t.apply(0, ctl(a, join(a, 'Ada')));
  enter(t, a, b, 'Bob');
  t.apply(1, ctl(b, keysFor(b, newChain(sodium, 1), a)));
  assert.ok(t.cloned, 'a signed delivery we never posted, at any place');
});

test('a receiving key seen once cannot be rolled back, and deliveries to a long-replaced key are noticed', () => {
  const a = person(0);
  const b = person(1);
  const k2 = sodium.crypto_box_keypair();
  // Ada's tab knew Bob's key 2; a history leaving out Bob's box records
  // still has her seal to it.
  const s = new RoomState(sodium, key, ROOM, { slot: 0, signPublic: a.sign.publicKey, boxes: new Map([[0, { publicKey: a.box.publicKey, secretKey: a.box.privateKey }]]) }, new Map(), {
    known: new Map([[1, b.sign.publicKey]]),
    boxes: new Map([[1, { n: 2, key: k2.publicKey }]]),
  });
  s.apply(0, ctl(a, join(a, 'Ada')));
  s.apply(1, ctl(b, join(b, 'Bob')));
  assert.equal(s.members.get(1)!.boxN, 2);
  assert.deepEqual(s.members.get(1)!.boxKey, k2.publicKey);
  assert.equal(s.apply(1, ctl(b, { t: 'box', id: id(), time: 1, n: 1, box: encodeKey(sodium, sodium.crypto_box_keypair().publicKey) })), null, 'an older number');
  assert.equal(s.apply(1, ctl(b, { t: 'box', id: id(), time: 1, n: 2, box: encodeKey(sodium, sodium.crypto_box_keypair().publicKey) })), null);
  assert.deepEqual(s.members.get(1)!.boxKey, k2.publicKey, 'the first key under a number stays');
  // Both records are Bob's, signed: evidence against him, not a changed history.
  assert.equal(s.conflict, false, 'a member cannot end the room for everyone');
  assert.equal(s.forks.get(1), 'keys');
  // Bob's own tab: a delivery sealed to key 0 long after he replaced it.
  const old = sodium.crypto_box_keypair();
  const t = new RoomState(sodium, key, ROOM, { slot: 1, signPublic: b.sign.publicKey, boxes: new Map([[0, { publicKey: old.publicKey, secretKey: old.privateKey }]]) });
  t.apply(0, ctl(a, join(a, 'Ada')));
  t.apply(1, ctl(b, { ...join(b, 'Bob'), box: encodeKey(sodium, old.publicKey) }));
  t.apply(0, ctl(a, admit(b)));
  t.apply(1, ctl(b, { t: 'box', id: id(), time: 1_000, n: 1, box: encodeKey(sodium, sodium.crypto_box_keypair().publicKey) }));
  const chain = newChain(sodium, 1);
  const late: ControlRecord = { t: 'keys', id: id(), time: 1_000 + 11 * 60_000, gen: 1, index: 0, commit: chainCommit(sodium, chain.ck, { roomId: ROOM, slot: 0, gen: 1, index: 0 }), to: [{ slot: 1, n: 0, box: sealChainKey(sodium, chain.ck, old.publicKey, { roomId: ROOM, slot: 0, gen: 1, index: 0 }, 1) }] };
  t.apply(0, ctl(a, late));
  assert.deepEqual([...t.staleFrom], [0], 'names the sender who signed it');
});

test('a forged join reusing a real join’s id does not hide it', () => {
  const a = person(0);
  const b = person(1);
  const m = person(1);
  const s = stateOf(a);
  s.apply(0, ctl(a, join(a, 'Ada')));
  const real = join(b, 'Bob');
  s.apply(1, ctl(m, { ...join(m, 'Bob'), id: real.id }));
  assert.equal(s.apply(1, ctl(b, real))?.kind, 'waiting');
  s.apply(0, ctl(a, inviteRec(1, 'Bob')));
  assert.equal(s.joinsToAdmit().get(1)?.length, 2, 'both are seen, so the creator admits neither');
});

test('the room record carries the end its creator set', () => {
  const a = person(0);
  const s = stateOf(a);
  s.apply(0, ctl(a, join(a, 'Ada')));
  s.apply(0, ctl(a, roomRec('', 123456)));
  assert.equal(s.ends, 123456);
});

test('message text rules also refuse invisible characters and blank-looking lines; emoji and words keep their joiners', () => {
  for (const bad of ['a\u{E0041}\u{E0042}', 'a\u200Bb', 'a\u2060b', 'a\uFEFFb', 'soft\u00ADhyphen', 'a\u2028b', 'a\u2029b', 'a\uFE00', 'x\u3164', 'a\n \n \n \nb',
    'e\u0301\u0301\u200D\u0301\u0301\u0301\u0301', 'a\u200Db', 'a\u200C', 'x\uFE0F\uFE0F', '\uFE0Fx']) {
    assert.ok(!validMessage(msg(bad)), JSON.stringify(bad));
  }
  for (const good of ['\u{1F469}\u{1F3FD}\u200D\u{1F4BB}', '\u{1F3F3}\uFE0F\u200D\u{1F308}', '\u2764\uFE0F\u200D\u{1F525}', '1\uFE0F\u20E3', '\u0645\u06CC\u200C\u062E\u0648\u0627\u0647\u0645', '\u2764\uFE0F ok']) {
    assert.ok(validMessage(msg(good)), JSON.stringify(good));
  }
  assert.equal(cleanText('a\u2028b\u{E0041} \n \n \n \n c\u200B'), 'a\nb\n\n\n c', 'line breaks, not indents, are trimmed');
  // Whatever cleanText leaves is accepted.
  const pool = ['a', 'Z', ' ', '\n', '\t', '\r', '\u0301', '\u200D', '\u200C', '\uFE0F', '\u2028', '\u202E', '\u{E0041}', '\u00AD', '\u{1F469}', '\u{1F3FD}', '\u0645', '\u3164', '\u0000'];
  for (let i = 0; i < 20_000; i++) {
    let t = '';
    const n = 1 + (i % 12);
    for (let j = 0; j < n; j++) t += pool[(i * 7 + j * 13 + ((i >> 3) * j)) % pool.length];
    const c = cleanText(t);
    if (c !== '') assert.ok(validMessage(msg(c)), JSON.stringify([t, c]));
  }
});

test('names hold at most four digits, and names in lookalike scripts always show a code', () => {
  for (const bad of ['Sam 12345', 'Sam \uFD3F12345 67890\uFD3E', 'Sam \u239B12345\u239E', 'Sam |12345|', 'Sam 1 2 3 4 5']) assert.ok(!nameAllowed(bad), bad);
  for (const good of ['Agent 47', 'Room 2026']) assert.ok(nameAllowed(good), good);
  const a = person(0);
  const b = person(1);
  const s = stateOf(a);
  s.apply(0, ctl(a, join(a, 'MAX')));
  assert.equal(s.tagOf(0), null);
  enter(s, a, b, '\u039C\u0391\u03A7'); // Greek capitals
  assert.match(s.nameOf(1), /\(\d{5} \d{5} \d{5}\)$/, 'a Greek "MAX"');
  assert.match(s.nameOf(0), /\(\d{5} \d{5} \d{5}\)$/, 'and the Latin one beside it');
  const t = stateOf(a);
  t.apply(0, ctl(a, join(a, 'Ada')));
  enter(t, a, b, '\uA4EC\uA4F3\uA4F4'); // "YOU" in Lisu
  assert.match(t.nameOf(1), /\(\d{5} \d{5} \d{5}\)$/);
});

test('a removal counts in the creator’s tab before the room hears of it', () => {
  const a = person(0);
  const b = person(1);
  const c = person(2);
  const s = stateOf(a);
  s.apply(0, ctl(a, join(a, 'Ada')));
  s.apply(0, ctl(a, inviteRec(1, 'Bob')));
  s.apply(0, ctl(a, inviteRec(2, 'Cleo')));
  enter(s, a, b, 'Bob');
  s.apply(2, ctl(c, join(c, 'Cleo')));
  assert.equal(s.joinsToAdmit().size, 1);
  s.removeLocally(1);
  s.removeLocally(2);
  assert.deepEqual(s.recipients(), []);
  assert.equal(s.joinsToAdmit().size, 0);
  assert.ok(!s.removalSeen.has(1), 'not announced yet');
  assert.equal(s.apply(0, ctl(a, { t: 'remove', id: id(), time: 2, slot: 1 }))?.kind, 'removed');
  assert.ok(s.removalSeen.has(1));
});

test('names, labels and the room name are hidden from anyone who holds only the room key', () => {
  const a = person(0);
  const b = person(1);
  const records = [ctl(a, join(a, 'Ada')), ctl(a, roomRec('Weekend trip')), ctl(a, inviteRec(1, 'Bob from work')), ctl(b, join(b, 'Bob')), ctl(a, admit(b, 'Bob'))];
  // The room key opens every control record, but no name is in them.
  for (const bytes of records) {
    const json = JSON.stringify(openControl(sodium, key, ROOM, bytes[0] === 1 ? 0 : 1, bytes)?.record ?? openControl(sodium, key, ROOM, 1, bytes)?.record);
    for (const secret of ['Ada', 'Weekend', 'Bob', 'work']) assert.ok(!json.includes(secret), `${secret} in ${json.slice(0, 60)}`);
  }
  // Someone with the room key and no roster key sees no names.
  const outsider = stateOf(person(5));
  const c = person(2);
  outsider.apply(0, records[0]!);
  outsider.apply(0, records[1]!);
  outsider.apply(0, records[2]!);
  assert.equal(outsider.name, '');
  assert.equal(outsider.nameOf(0), 'The creator');
  assert.equal(outsider.labels.get(1), '');
  // Bob learns them all once the creator lets him in.
  const s = stateOf(b);
  for (const [i, bytes] of records.entries()) s.apply(i === 3 ? 1 : 0, bytes);
  assert.equal(s.name, 'Weekend trip');
  assert.equal(s.nameOf(0), 'Ada');
  assert.equal(s.nameOf(1), 'Bob');
  assert.equal(s.labels.get(1), 'Bob from work');
  assert.ok(s.rosterVersion > 0);
  assert.deepEqual(s.rosterKey(), ROSTER);
  // The creator reads a joiner's sealed name before letting them in; nobody else can.
  const creator = stateOf(a);
  creator.apply(0, records[0]!);
  creator.apply(2, ctl(c, join(c, 'Cleo')));
  assert.equal(creator.joinsToAdmit().size, 0, 'no invite for that place yet');
  const cj = join(c, 'Cleo') as ControlRecord & { t: 'join' };
  const cPlace = { roomId: ROOM, slot: 2, key: cj.key, box: cj.box };
  assert.equal(openSealedName(sodium, cj.name, NAMES.publicKey, NAMES.privateKey, cPlace), 'Cleo');
  assert.equal(openSealedName(sodium, cj.name, NAMES.publicKey, NAMES.privateKey, { ...cPlace, slot: 3 }), null, 'bound to its place');
  assert.equal(openSealedName(sodium, cj.name, NAMES.publicKey, NAMES.privateKey, { ...cPlace, key: encodeKey(sodium, b.sign.publicKey) }), null, 'and to its keys');
  assert.equal(openBoxedName(sodium, sodium.randombytes_buf(32), (roomRec('x') as { name: string }).name, ROOM, 'room', 0), null);
  // A roster key sealed to one member opens for nobody else, nor for another place.
  const sealed = sealRoster(sodium, ROSTER, b.box.publicKey, ROOM, 1);
  assert.deepEqual(openRoster(sodium, sealed, b.box.publicKey, b.box.privateKey, ROOM, 1), ROSTER);
  assert.equal(openRoster(sodium, sealed, b.box.publicKey, b.box.privateKey, ROOM, 2), null);
  // Only the creator's join may carry a name key.
  assert.ok(!validControl({ ...join(person(3), 'x'), namekey: encodeKey(sodium, NAMES.publicKey) }));
  const { namekey: _, ...noKey } = join(a, 'Ada') as ControlRecord & { namekey?: string };
  assert.ok(!validControl(noKey), 'and the creator’s must');
});

test('a sender who hands members different chains for one place is caught', () => {
  const a = person(0);
  const b = person(1);
  const c = person(2);
  const s = stateOf(b);
  s.apply(0, ctl(a, join(a, 'Ada')));
  enter(s, a, b, 'Bob');
  enter(s, a, c, 'Cleo');
  const ada = newChain(sodium, 1);
  s.apply(0, ctl(a, keysFor(a, ada, b)));
  assert.equal(s.forks.size, 0);
  // Ada gives Cleo another chain at the same place: Bob, holding the real one, sees the commitment does not match.
  const other = newChain(sodium, 1);
  s.apply(0, ctl(a, keysFor(a, other, c)));
  assert.equal(s.forks.get(0), 'keys');
  // A delivery to us whose key does not match its commitment is refused too.
  const t = stateOf(b);
  t.apply(0, ctl(a, join(a, 'Ada')));
  enter(t, a, b, 'Bob');
  const lie = { ...keysFor(a, ada, b), commit: chainCommit(sodium, other.ck, { roomId: ROOM, slot: 0, gen: 1, index: 0 }) } as ControlRecord;
  assert.equal(t.apply(0, ctl(a, lie)), null);
  assert.equal(t.forks.get(0), 'keys');
  assert.equal(t.chains.has(0), false);
});

test('keys that keep going to others after we were let in, but not to us, show we are being left out', () => {
  const a = person(0);
  const b = person(1);
  const c = person(2);
  let clock = 1_000_000;
  const s = stateOf(b);
  s.now = () => clock;
  s.apply(0, ctl(a, join(a, 'Ada')));
  enter(s, a, b, 'Bob');
  enter(s, a, c, 'Cleo');
  const g1 = newChain(sodium, 1);
  s.apply(0, ctl(a, keysFor(a, g1, c)));
  clock += 121_000;
  assert.deepEqual(s.skipped(120_000), [], 'one delivery is not enough: a sender with a stale view, gone offline');
  s.apply(0, sealMessage(sodium, g1, ROOM, 0, a.sign.privateKey, msg('for Cleo')));
  assert.deepEqual(s.skipped(120_000), [0], 'then a message on that chain');
  assert.deepEqual(s.skipped(10 * 60_000), [], 'and only once it has lasted');
  // Once our delivery comes, it is over.
  s.apply(0, ctl(a, keysFor(a, newChain(sodium, 2), b, c)));
  assert.deepEqual(s.skipped(0), []);
  // Keys from before we were let in are no sign of anything.
  const t = stateOf(c);
  t.apply(0, ctl(a, join(a, 'Ada')));
  enter(t, a, b, 'Bob');
  t.apply(0, ctl(a, keysFor(a, newChain(sodium, 1), b)));
  enter(t, a, c, 'Cleo');
  assert.deepEqual(t.skipped(0), []);
});

test('a sender whose records step back is splitting the room', () => {
  const a = person(0);
  const b = person(1);
  const c = person(2);
  const m = person(3);
  const s = stateOf(b);
  s.apply(0, ctl(a, join(a, 'Ada')));
  enter(s, a, b, 'Bob');
  enter(s, a, c, 'Cleo');
  enter(s, a, m, 'Mal');
  // Mal gives everyone generation 1, then generation 2 to Bob only, then
  // writes on generation 1 again (for Cleo).
  const g1 = newChain(sodium, 1);
  s.apply(3, ctl(m, keysFor(m, g1, b, c)));
  const g2 = newChain(sodium, 2);
  s.apply(3, ctl(m, keysFor(m, g2, b)));
  assert.equal(s.forks.size, 0);
  s.apply(3, sealMessage(sodium, g1, ROOM, 3, m.sign.privateKey, msg('north gate')));
  assert.equal(s.forks.get(3), 'order');
  // A delivery far ahead of the chain we hold is no honest step either.
  const t = stateOf(b);
  t.apply(0, ctl(a, join(a, 'Ada')));
  enter(t, a, b, 'Bob');
  enter(t, a, c, 'Cleo');
  const ada = newChain(sodium, 1);
  t.apply(0, ctl(a, keysFor(a, ada, b)));
  const far = copy(ada);
  advanceChain(sodium, far, 2000);
  t.apply(0, ctl(a, keysFor(a, far, c)));
  assert.equal(t.forks.get(0), 'keys');
  // A replayed message is not a step back.
  const u = stateOf(b);
  u.apply(0, ctl(a, join(a, 'Ada')));
  enter(u, a, b, 'Bob');
  const ada2 = newChain(sodium, 1);
  u.apply(0, ctl(a, keysFor(a, ada2, b)));
  const once = sealMessage(sodium, ada2, ROOM, 0, a.sign.privateKey, msg('once'));
  u.apply(0, once);
  u.apply(0, once);
  assert.equal(u.forks.size, 0);
});

test('receipts show when two members read different messages at the same place', () => {
  const a = person(0);
  const b = person(1);
  const c = person(2);
  const s = stateOf(b);
  s.apply(0, ctl(a, join(a, 'Ada')));
  enter(s, a, b, 'Bob');
  enter(s, a, c, 'Cleo');
  const ada = newChain(sodium, 1);
  const cleo = newChain(sodium, 1);
  s.apply(0, ctl(a, keysFor(a, ada, b, c)));
  s.apply(2, ctl(c, keysFor(c, cleo, b)));
  const hi = msg('hi');
  s.apply(0, sealMessage(sodium, ada, ROOM, 0, a.sign.privateKey, hi));
  const acks = s.acks();
  assert.equal(acks.length, 20, 'one receipt per place, always');
  assert.deepEqual([acks[0]!.slot, acks[0]!.gen, acks[0]!.index, acks[0]!.h], [0, 1, 0, contentHash(sodium, hi)]);
  assert.ok(acks.slice(1).every((x) => x.gen === 0 && x.h === NO_ACK));
  assert.ok(validMessage({ ...msg('x'), seen: acks }));
  assert.ok(!validMessage({ ...msg('x'), seen: acks.slice(1) }), 'not fewer');
  // Cleo agrees about Ada's message: nothing.
  s.apply(2, sealMessage(sodium, cleo, ROOM, 2, c.sign.privateKey, { ...msg('same'), seen: receipts({ slot: 0, gen: 1, index: 0, h: contentHash(sodium, hi) }) }));
  assert.equal(s.forkNotes.size, 0);
  // Cleo read something else there.
  s.apply(2, sealMessage(sodium, cleo, ROOM, 2, c.sign.privateKey, { ...msg('other'), seen: receipts({ slot: 0, gen: 1, index: 0, h: contentHash(sodium, msg('not hi')) }) }));
  assert.ok(s.forkNotes.has('2:0'));
  // A receipt about a place we have not read yet is checked when we read it.
  const t = stateOf(b);
  t.apply(0, ctl(a, join(a, 'Ada')));
  enter(t, a, b, 'Bob');
  enter(t, a, c, 'Cleo');
  const ada2 = newChain(sodium, 1);
  const cleo2 = newChain(sodium, 1);
  t.apply(0, ctl(a, keysFor(a, ada2, b, c)));
  t.apply(2, ctl(c, keysFor(c, cleo2, b)));
  t.apply(2, sealMessage(sodium, cleo2, ROOM, 2, c.sign.privateKey, { ...msg('early'), seen: receipts({ slot: 0, gen: 1, index: 0, h: contentHash(sodium, msg('something else')) }) }));
  assert.equal(t.forkNotes.size, 0);
  t.apply(0, sealMessage(sodium, ada2, ROOM, 0, a.sign.privateKey, hi));
  assert.ok(t.forkNotes.has('2:0'));
});

test('real-world text keeps its joiners, flags and marks; hidden characters still go', () => {
  const good = [
    '\u0DC1\u0DCA\u200D\u0DBB\u0DD3', // Sinhala sri
    '\u0D05\u0D35\u0D28\u0D4D\u200D', // Malayalam chillu
    '\u09B0\u200D\u09CD\u09AF', // Bengali ra-phala
    '\u0915\u094D\u200D\u0937', // Devanagari half form
    '\u{1F3F4}\u{E0067}\u{E0062}\u{E0065}\u{E006E}\u{E0067}\u{E007F}', // England
    '\u101C\u103B\u103E\u1031\u102C\u1037', // Burmese
    '\u0F66\u0F92\u0FB2\u0F7C\u0F63\u0F0B\u0F58', // Tibetan Dolma
    '\u05E9\u05B8\u05BC\u05C1', // Hebrew with full pointing
    '  indented first line',
  ];
  for (const t of good) {
    assert.ok(validMessage(msg(t)), JSON.stringify(t));
    assert.equal(cleanText(t), t, JSON.stringify(t));
  }
  for (const bad of ['pay\uFE0Fpal', 'a\u034Fb', 'a\u17B4b', '\u1820\u180Bx', 'a\n\u2800\n\u2800\n\u2800\nb', '\nlead', '\u{1F3F4}\u{E0067}', 'a\u200D\u200Db']) {
    assert.ok(!validMessage(msg(bad)), JSON.stringify(bad));
  }
  for (const name of ['\u1000\u103B\u1031\u102C\u103A', '\u0F66\u0F92\u0FB2\u0F7C\u0F63\u0F0B\u0F58', '\u05E9\u05B8\u05BC\u05C1\u05D9']) assert.ok(nameAllowed(name), name);
  assert.ok(!nameAllowed('Ada \u2713'), 'no check marks');
  assert.ok(nameAllowed('Q4 2025 planning, Trip 2025/26', true), 'years in a room name');
  assert.ok(!nameAllowed('Q4 2025 planning'), 'but not in a person’s name');
  assert.ok(nameAllowed('Class of \u201899'.replace('99', '9')), 'a smart quote is no bracket');
});

test('after a reload, members still read everyone’s names', () => {
  const a = person(0);
  const b = person(1);
  const c = person(2);
  const records: [number, Uint8Array][] = [
    [0, ctl(a, join(a, 'Ada'))], [1, ctl(b, join(b, 'Bob'))], [0, ctl(a, admit(b, 'Bob'))], [2, ctl(c, join(c, 'Cleo'))], [0, ctl(a, admit(c, 'Cleo'))],
  ];
  // Bob's tab after a reload: it pinned everyone's keys and kept the roster key.
  const s = new RoomState(sodium, key, ROOM, {
    slot: 1, signPublic: b.sign.publicKey, boxes: new Map([[0, { publicKey: b.box.publicKey, secretKey: b.box.privateKey }]]), roster: ROSTER,
  }, new Map(), { known: new Map([[0, a.sign.publicKey], [1, b.sign.publicKey], [2, c.sign.publicKey]]) });
  for (const [from, bytes] of records) s.apply(from, bytes);
  assert.deepEqual([0, 1, 2].map((x) => s.nameOf(x)), ['Ada', 'Bob', 'Cleo']);
  // And without the roster key saved: their own admit, replayed, brings it.
  const t = new RoomState(sodium, key, ROOM, {
    slot: 1, signPublic: b.sign.publicKey, boxes: new Map([[0, { publicKey: b.box.publicKey, secretKey: b.box.privateKey }]]),
  }, new Map(), { known: new Map([[0, a.sign.publicKey], [1, b.sign.publicKey], [2, c.sign.publicKey]]) });
  for (const [from, bytes] of records) t.apply(from, bytes);
  assert.deepEqual([0, 1, 2].map((x) => t.nameOf(x)), ['Ada', 'Bob', 'Cleo']);
});

test('invisible and unassigned characters, stray joiners and unknown flags cannot hide text', () => {
  for (const bad of ['pay\u2065pal.com', '\u2065', '\u2800\u2800', 'pay\u200Cpal', 'e\u0301\u200Dvil', 'x\u{E0002}y',
    '\u{1F3F4}\u{E0077}\u{E0069}\u{E0072}\u{E0065}\u{E007F}']) {
    assert.ok(!validMessage(msg(bad)), JSON.stringify(bad));
  }
  for (const good of ['\u{1F3F4}\u{E0067}\u{E0062}\u{E0073}\u{E0063}\u{E0074}\u{E007F}', '\u0645\u06CC\u200C\u062E\u0648\u0627\u0647\u0645', '\u2800 art \u2800']) {
    assert.ok(validMessage(msg(good)), JSON.stringify(good));
  }
  assert.equal(cleanText('pay\u2065pal'), 'paypal');
  assert.equal(cleanText('\u{1F3F4}\u{E0077}\u{E0069}\u{E0072}\u{E0065}\u{E007F} hi'), '\u{1F3F4} hi');
});

test('names cannot imitate the verified mark, or hide "you"', () => {
  for (const bad of ['Bob (verified)', 'Bob verified', 'Bob \u{1F5F9}', 'Bob \u{10102}', 'Bob \u237B']) assert.ok(!nameAllowed(bad), bad);
  const a = person(0);
  const b = person(1);
  const s = stateOf(a);
  s.apply(0, ctl(a, join(a, 'Ada')));
  enter(s, a, b, 'Yo\u2065u');
  // cleanName removes the invisible character, so the name never gets in.
  assert.equal(s.members.get(1)!.name, '');
});

const cp = (...c: number[]) => String.fromCodePoint(...c);

test('names must show something, and cannot claim a role, a placeholder or "verified" in lookalike letters', () => {
  for (const bad of [
    cp(0x200d), cp(0x301), cp(0x200d, 0x301), // nothing visible
    'Ada (admin)', 'Support', 'Room owner', 'Moderator', 'Nullbin', 'adm1n', // roles the room does not have
    'The creator', 'Member 3', 'Member', 'MEMBER 12', // what the app shows for people with no name
    `v${cp(0x1d07)}rified`, 'ver1fied', `v${cp(0x435)}rified`, // "verified" in lookalikes
    `Bob ${cp(0x3007).repeat(5)}`, `Bob (${cp(0x3007)})`, // digits of any kind
  ]) assert.ok(!nameAllowed(bad), JSON.stringify(bad));
  for (const good of ['Ada', 'Modi', 'Ada Lovelace', cp(0x1f600), 'Mo', 'Jo 1234', 'Members club']) assert.ok(nameAllowed(good), good);
  assert.ok(nameAllowed(''), 'an empty label is allowed');
});

test('a name that holds another member’s name gets a code, and so does the other', () => {
  for (const fake of ['Sam (work)', 'Sam2', 'Sam - laptop', 'Sam [work]', 'Real Sam', 'S a m', cp(0xa731, 0x1d00, 0x1d0d)]) assert.ok(resembles('Sam', fake), fake);
  for (const other of ['Ada', 'Bob', 'Max']) assert.ok(!resembles('Sam', other), other);
  const a = person(0);
  const b = person(1);
  const c = person(2);
  const s = stateOf(a);
  s.apply(0, ctl(a, join(a, 'Ada')));
  enter(s, a, b, 'Sam');
  enter(s, a, c, 'Sam (work)');
  assert.notEqual(s.tagOf(1), null);
  assert.notEqual(s.tagOf(2), null);
  // "You" in small capitals is still "you".
  const d = person(3);
  enter(s, a, d, cp(0x28f, 0x1d0f, 0x1d1c));
  assert.notEqual(s.tagOf(3), null);
});

test('a delivery for us that will not open counts as being left out', () => {
  const a = person(0);
  const b = person(1);
  const c = person(2);
  let clock = 1_000_000;
  const s = stateOf(b);
  s.now = () => clock;
  s.apply(0, ctl(a, join(a, 'Ada')));
  enter(s, a, b, 'Bob');
  enter(s, a, c, 'Cleo');
  const junk = sodium.crypto_box_keypair();
  for (const gen of [1, 2]) {
    const chain = newChain(sodium, gen);
    const place = { roomId: ROOM, slot: 0, gen, index: 0 };
    const r = keysFor(a, chain, c) as ControlRecord & { t: 'keys' };
    // Bob's entry is there, but sealed to a key he never had.
    r.to.push({ slot: 1, n: 0, box: sealChainKey(sodium, chain.ck, junk.publicKey, place, 1) });
    s.apply(0, ctl(a, r));
  }
  clock += 121_000;
  assert.deepEqual(s.skipped(120_000), [0]);
});

test('a receiving-key number cannot jump far ahead and shut out the member’s own later keys', () => {
  const a = person(0);
  const b = person(1);
  const s = stateOf(a);
  s.apply(0, ctl(a, join(a, 'Ada')));
  enter(s, a, b, 'Bob');
  const boxRec = (n: number): ControlRecord => ({ t: 'box', id: id(), time: 1, n, box: encodeKey(sodium, sodium.crypto_box_keypair().publicKey) });
  assert.ok(!validControl(boxRec(MAX_BOX_N + 1)));
  assert.equal(s.apply(1, ctl(b, boxRec(65))), null, 'too far ahead');
  assert.equal(s.members.get(1)!.boxN, 0);
  assert.equal(s.forks.get(1), 'order');
  assert.notEqual(s.apply(1, ctl(b, boxRec(1))), null, 'the next number still works');
  assert.equal(s.members.get(1)!.boxN, 1);
});

test('the creator closes a place two people proved they had the link for, and notices a damaged invite', () => {
  const a = person(0);
  const b = person(1);
  const b2 = person(1);
  const secret = sodium.randombytes_buf(32);
  const s = new RoomState(sodium, key, ROOM, {
    slot: 0, signPublic: a.sign.publicKey, boxes: new Map([[0, { publicKey: a.box.publicKey, secretKey: a.box.privateKey }]]),
    roster: ROSTER, nameSecret: NAMES.privateKey,
    checkProof: (slot, j) => (slot === 1 ? j.proof !== null && checkJoinProof(sodium, secret, ROOM, slot, j.key, j.box, j.proof) : null),
  });
  const withProof = (p: Person, sec: Uint8Array): ControlRecord => {
    const j = join(p, 'Bob') as ControlRecord & { t: 'join' };
    return { ...j, proof: joinProof(sodium, sec, ROOM, p.slot, j.key, j.box) };
  };
  s.apply(0, ctl(a, join(a, 'Ada')));
  s.apply(0, ctl(a, inviteRec(1, 'Bob')));
  // A join whose proof fails is not kept, and is noticed.
  s.apply(1, ctl(b2, withProof(b2, sodium.randombytes_buf(32))));
  assert.ok(s.badProof.has(1));
  assert.equal(s.joinsToAdmit().get(1), undefined);
  // The real one is admitted; a second valid one after that is contested.
  s.apply(1, ctl(b, withProof(b, secret)));
  s.apply(0, ctl(a, admit(b, 'Bob')));
  assert.equal(s.contested.size, 0);
  s.apply(1, ctl(b2, withProof(b2, secret)));
  assert.ok(s.contested.has(1));
});

test('wiping the state forgets keys and what was decrypted', () => {
  const a = person(0);
  const b = person(1);
  const s = stateOf(b);
  s.apply(0, ctl(a, join(a, 'Ada')));
  enter(s, a, b, 'Bob');
  const chain = newChain(sodium, 1);
  s.apply(0, ctl(a, keysFor(a, copy(chain), b)));
  s.apply(0, sealMessage(sodium, chain, ROOM, 0, a.sign.privateKey, msg('secret words')));
  assert.equal(s.messages.length, 1);
  assert.equal(s.members.get(0)!.name, 'Ada');
  s.wipe();
  assert.equal(s.messages.length, 0);
  assert.equal(s.members.get(0)!.name, '');
});

test('two deliveries for one place with different chains are caught by everyone, even members who got neither', () => {
  const a = person(0);
  const b = person(1);
  const c = person(2);
  const d = person(3);
  const s = stateOf(d);
  s.apply(0, ctl(a, join(a, 'Ada')));
  enter(s, a, b, 'Bob');
  enter(s, a, c, 'Cleo');
  enter(s, a, d, 'Dan');
  s.apply(0, ctl(a, keysFor(a, newChain(sodium, 1), b)));
  assert.equal(s.forks.get(0), undefined);
  s.apply(0, ctl(a, keysFor(a, newChain(sodium, 1), c)));
  assert.equal(s.forks.get(0), 'keys');
  assert.equal(s.conflict, false);
});

test('a joiner whose invite link was changed on the way finds out from the creator’s signed invite', () => {
  const a = person(0);
  const b = person(1);
  const secret = sodium.randombytes_buf(32);
  const joiner = (check: string) => {
    const s = new RoomState(sodium, key, ROOM, {
      slot: 1, signPublic: b.sign.publicKey, boxes: new Map([[0, { publicKey: b.box.publicKey, secretKey: b.box.privateKey }]]), inviteCheck: check,
    });
    s.apply(0, ctl(a, join(a, 'Ada')));
    s.apply(0, ctl(a, inviteRec(1, 'Bob', secret)));
    return s;
  };
  assert.equal(joiner(inviteCheck(sodium, secret, ROOM, 1)).inviteMismatch, false);
  assert.equal(joiner(inviteCheck(sodium, sodium.randombytes_buf(32), ROOM, 1)).inviteMismatch, true);
  // Only the creator signs invites: a member's is refused, and says nothing.
  const s = joiner(inviteCheck(sodium, secret, ROOM, 1));
  const c = person(2);
  enter(s, a, c, 'Cleo');
  assert.equal(s.apply(2, ctl(c, inviteRec(1, 'Bob'))), null);
  assert.equal(s.inviteMismatch, false);
});
