// Null Chat cryptography. Everything here runs in the browser.
//
// Two layers:
//
// 1. Control records (version 1): who is in the room, the room's name, invite
//    labels, removals and key deliveries. They are encrypted with a subkey of
//    the room key (crypto_kdf context "nbroomen"), which travels only in
//    invite links after the #. XChaCha20-Poly1305, fresh random nonce, with
//    additional data binding the record to its room and to the slot the
//    server says sent it. Names, the room's name and labels inside them are
//    encrypted again, under a roster key that only admitted members get
//    (sealed to them in the creator's admit), padded to one size: the room
//    key alone, which every invite link carries, shows none of them.
//
// 2. Messages (version 2), with forward secrecy ("sender keys", as in Signal
//    and WhatsApp groups). Every member has their own sending chain: a 32-byte
//    chain key CK that steps forward after each message,
//      message key  = crypto_kdf(CK, 1, "nbrmmsgk")
//      next CK      = crypto_kdf(CK, 1, "nbrmnext")
//    and each key is deleted once used. A member hands their current CK to
//    each other member in a "keys" control record, sealed to that member's
//    current X25519 receiving key (crypto_box_seal), together with a hash
//    binding it to the room, the sender's slot and the chain position, so
//    the room key alone cannot read any message and nobody can pass off
//    another member's chain as theirs. Chains restart from a fresh random CK (a new
//    generation) when someone is removed and every 50 messages; a removed
//    member never gets the new ones.
//
//    Receiving keys rotate too: soon after a delivery arrives, the member
//    announces a new X25519 key (a numbered "box" record) and deletes the
//    old secret a little later. So a delivery recorded today cannot be
//    opened with a key stolen from the member's device later on.
//
// Every record is signed (Ed25519) by its sender. A member's signing key and
// X25519 key arrive in their own join record, signed with that signing key.
//
// Wire formats (what the server stores):
//   control: 1 || nonce (24) || AEAD(plaintext, AD = "nullbin room v1 <room> <slot>")
//   message: 2 || generation (4, BE) || index (4, BE) || nonce (24) ||
//            AEAD(plaintext, key = message key,
//                 AD = "nullbin room msg v1 <room> <slot> <generation> <index>") ||
//            outer signature (64): Ed25519, by the sender, over everything
//            before it. Every reader checks it before decrypting, so nobody
//            can strip or change it; and a member's own tab, which cannot
//            decrypt its own messages, can still tell them from a copy's.
//   plaintext: length of JSON (4, BE) || JSON || signature (64) || zeros, to
//              paddedLength(n, 1024): a record's size shows only a range.
// Signatures cover "nullbin room record v1\0<room>\0<slot>\0" || JSON for
// control records, and "nullbin room message v1\0<room>\0<slot>\0<generation>
// \0<index>\0" || JSON for messages.

import { FLAG_TAGS, HIDDEN, hasHiddenChars, joinerOk } from './hidden.ts';
import type { Sodium } from './sodium.ts';
import { paddedLength } from './format.ts';
import { cleanName } from './comments.ts';
import { cleanFileName } from './zip.ts';

export const ROOM_KEY_BYTES = 32;
export const CONTROL_VERSION = 1;
export const MESSAGE_VERSION = 3;
export const RECORD_MIN_PADDED = 1024;
/** Messages pad to at least this: their receipts (one per place) take about 1.2 KiB, and short messages should all be one size. */
export const MESSAGE_MIN_PADDED = 2048;
/** Must match the server's limit. */
export const MAX_RECORD_BYTES = 16 * 1024;
export const MAX_SLOTS = 20;
/** The smallest member limit a room may set: its creator and one other. */
export const MIN_MEMBERS = 2;
/** How long an unused invite may work, in seconds: a room picks one. */
export const INVITE_TTLS: readonly number[] = [300, 900, 3600];
/** Longest password accepted (UTF-8 bytes after NFC). */
export const MAX_ROOM_PASSWORD_BYTES = 1024;
export const MAX_MESSAGE_LENGTH = 2000;
export const MAX_NAME_LENGTH = 40;
export const MAX_ROOM_NAME_LENGTH = 40; // names are cleaned like comment names (40 at most)
/** A reader skips at most this many message keys ahead in one chain. */
export const MAX_SKIP = 200; // honest senders start a new chain every 50 messages
/** Largest generation or index. */
export const MAX_COUNTER = 0x7fffffff;
/**
 * The highest receiving-key number. A room holds at most 1,000 records, so
 * an honest member never gets near it; a far larger number could only shut
 * out the member's real later keys.
 */
export const MAX_BOX_N = 4096;
/** Largest millisecond timestamp supported by JavaScript Date. */
const MAX_TIME = 8_640_000_000_000_000;

const LENGTH_BYTES = 4;
const SIG_BYTES = 64;
const NONCE_BYTES = 24;
const TAG_BYTES = 16;
const MESSAGE_HEAD = 1 + 4 + 4 + NONCE_BYTES;
const OUTER_SIG_BYTES = 64;
const BINDING_BYTES = 16;
const SEALED_KEY_BYTES = 32 + BINDING_BYTES + 48; // crypto_box_seal of a chain key and its binding
const ID = /^[0-9a-f]{32}$/;
const B64URL_32 = /^[A-Za-z0-9_-]{43}$/;
const B64URL_SEALED = /^[A-Za-z0-9_-]{128}$/;
const B64URL_16 = /^[A-Za-z0-9_-]{22}$/;

/** Control records: encrypted with the room key. */
export type ControlRecord =
  // name: boxName(roster key, "room"); ends: when the room ends (ms); pw:
  // joins must also prove the room's password; max: the most members at
  // once, the creator included; ttl: how long an invite works (seconds).
  | { t: 'room'; id: string; time: number; name: string; ends: number; pw: boolean; max: number; ttl: number }
  // name: the creator's own, boxName(roster key, "member", 0), with namekey,
  // the X25519 key joiners seal their names to; anyone else's, sealName(namekey).
  | { t: 'join'; id: string; time: number; name: string; key: string; box: string; proof?: string; namekey?: string }
  // label: boxName(roster key, "label", slot).
  // exp: when the invite stops working (ms, the creator's clock).
  | { t: 'invite'; id: string; time: number; slot: number; label: string; check: string; exp: number }
  | { t: 'remove'; id: string; time: number; slot: number }
  // roster: the roster key sealed to the member's join key; name: boxName(roster key, "member", slot).
  | { t: 'admit'; id: string; time: number; slot: number; key: string; roster: string; name: string }
  | { t: 'keys'; id: string; time: number; gen: number; index: number; commit: string; to: { slot: number; n: number; box: string }[] }
  | { t: 'box'; id: string; time: number; n: number; box: string };

/**
 * The reactions anyone can add. A fixed set: no arbitrary characters, so a
 * reaction cannot carry hidden text. Written as escapes, since one includes
 * a variation selector.
 */
export const REACTIONS: readonly string[] = ['\u{1F44D}', '\u2764\uFE0F', '\u{1F602}', '\u{1F62E}', '\u{1F622}', '\u{1F64F}'];

/** A message a reply or reaction is about: its id and the slot of its sender. */
export interface Ref {
  id: string;
  author: number;
}

/**
 * A receipt: the newest chat record its sender had read from one member,
 * by its place in that member's chain, and a hash of its content. Members
 * who read something else at that place see that the room was forked.
 */
export interface Ack {
  slot: number;
  gen: number;
  index: number;
  h: string;
}

/**
 * The sender's previous chat record, which each chat record commits to: its
 * place in the sender's chains and a hash of its content (as in receipts).
 * So a record's hash covers all its sender's earlier ones, and a sender who
 * shows two members different records at one place contradicts, in a later
 * record signed with its own key, what one of them read. Null only for a
 * sender's first record.
 */
export interface Prev {
  gen: number;
  index: number;
  h: string;
}

/** An encrypted file shared in chat via a Paste-bridge link. */
export interface ChatFile {
  id: string;
  key: string;
  name: string;
  size: number;
}

/**
 * Chat records, encrypted with one-time message keys: a message (maybe a
 * reply, maybe with an encrypted file, always with receipts), a reaction
 * added or taken back, an edit or an unsend of one's own message, or
 * receipts alone (posted by a tab that read messages but sent none for a
 * while, so a member shown a different message is not left unseen). Each
 * commits to its sender's previous one.
 */
export type MessageRecord =
  | { t: 'msg'; id: string; time: number; prev: Prev | null; text: string; reply: Ref | null; seen: Ack[]; file?: ChatFile }
  | { t: 'react'; id: string; time: number; prev: Prev | null; target: string; author: number; emoji: string; on: boolean }
  | { t: 'edit'; id: string; time: number; prev: Prev | null; target: string; text: string }
  | { t: 'unsend'; id: string; time: number; prev: Prev | null; target: string }
  | { t: 'seen'; id: string; time: number; prev: Prev | null; seen: Ack[] };

/** A decrypted record whose signature still has to be checked. */
export interface Opened<R> {
  record: R;
  signed: Uint8Array;
  signature: Uint8Array;
}

/** A position in a sending chain. */
export interface Chain {
  gen: number;
  index: number;
  ck: Uint8Array;
}

/** The key that encrypts this room's control records. */
export function controlKey(sodium: Sodium, roomKey: Uint8Array): Uint8Array {
  if (roomKey.length !== ROOM_KEY_BYTES) throw new Error('bad room key');
  return sodium.crypto_kdf_derive_from_key(32, 1, 'nbroomen', roomKey);
}

/** The key for the message at a chain position. */
export function messageKey(sodium: Sodium, ck: Uint8Array): Uint8Array {
  return sodium.crypto_kdf_derive_from_key(32, 1, 'nbrmmsgk', ck);
}

/** The next chain key. The caller deletes the old one. */
export function nextChainKey(sodium: Sodium, ck: Uint8Array): Uint8Array {
  return sodium.crypto_kdf_derive_from_key(32, 1, 'nbrmnext', ck);
}

/** Steps a chain forward to `index`, deleting every key it passes. */
export function advanceChain(sodium: Sodium, chain: Chain, index: number): void {
  while (chain.index < index) {
    const next = nextChainKey(sodium, chain.ck);
    sodium.memzero(chain.ck);
    chain.ck = next;
    chain.index++;
  }
}

/** A fresh chain: a new generation starting from a random key. */
export function newChain(sodium: Sodium, gen: number): Chain {
  if (!Number.isInteger(gen) || gen < 1 || gen > MAX_COUNTER) throw new Error('bad generation');
  return { gen, index: 0, ck: sodium.randombytes_buf(32) };
}

const enc = new TextEncoder();

function controlAD(roomId: string, slot: number): Uint8Array {
  return enc.encode(`nullbin room v1 ${roomId} ${slot}`);
}

function messageAD(roomId: string, slot: number, gen: number, index: number): Uint8Array {
  return enc.encode(`nullbin room msg v1 ${roomId} ${slot} ${gen} ${index}`);
}

function concat(head: Uint8Array, json: Uint8Array): Uint8Array {
  const out = new Uint8Array(head.length + json.length);
  out.set(head, 0);
  out.set(json, head.length);
  return out;
}

function controlSigned(roomId: string, slot: number, json: Uint8Array): Uint8Array {
  return concat(enc.encode(`nullbin room record v1\0${roomId}\0${slot}\0`), json);
}

function messageSigned(roomId: string, slot: number, gen: number, index: number, json: Uint8Array): Uint8Array {
  return concat(enc.encode(`nullbin room message v1\0${roomId}\0${slot}\0${gen}\0${index}\0`), json);
}

export function newRecordId(sodium: Sodium): string {
  return sodium.to_hex(sodium.randombytes_buf(16));
}

/** length || JSON || signature || zeros, padded. */
function layout(json: Uint8Array, signature: Uint8Array, min: number): Uint8Array {
  const plain = new Uint8Array(paddedLength(LENGTH_BYTES + json.length + SIG_BYTES, min));
  new DataView(plain.buffer).setUint32(0, json.length);
  plain.set(json, LENGTH_BYTES);
  plain.set(signature, LENGTH_BYTES + json.length);
  return plain;
}

/** The JSON and signature of a padded plaintext, or null if it is not canonical. */
function unlayout(plain: Uint8Array, min: number): { json: Uint8Array; signature: Uint8Array } | null {
  if (plain.length < LENGTH_BYTES + SIG_BYTES) return null;
  const length = new DataView(plain.buffer, plain.byteOffset, plain.byteLength).getUint32(0);
  // Exactly the padded length for this content, and only zeros after it.
  // This also rules out a length past the end.
  if (plain.length !== paddedLength(LENGTH_BYTES + length + SIG_BYTES, min)) return null;
  if (!plain.subarray(LENGTH_BYTES + length + SIG_BYTES).every((b) => b === 0)) return null;
  return {
    json: plain.slice(LENGTH_BYTES, LENGTH_BYTES + length),
    signature: plain.slice(LENGTH_BYTES + length, LENGTH_BYTES + length + SIG_BYTES),
  };
}

function parseJSON(json: Uint8Array): unknown {
  try {
    return JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(json));
  } catch {
    return undefined;
  }
}

/** Encrypts and signs one control record from `slot`. */
export function sealControl(sodium: Sodium, key: Uint8Array, roomId: string, slot: number, signSecret: Uint8Array, record: ControlRecord): Uint8Array {
  if (!validControl(record)) throw new Error('invalid record');
  const json = enc.encode(JSON.stringify(record));
  const plain = layout(json, sodium.crypto_sign_detached(controlSigned(roomId, slot, json), signSecret), RECORD_MIN_PADDED);
  const nonce = sodium.randombytes_buf(NONCE_BYTES);
  const ct = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(plain, controlAD(roomId, slot), null, nonce, key);
  plain.fill(0);
  const out = new Uint8Array(1 + NONCE_BYTES + ct.length);
  out[0] = CONTROL_VERSION;
  out.set(nonce, 1);
  out.set(ct, 1 + NONCE_BYTES);
  if (out.length > MAX_RECORD_BYTES) throw new Error('record too large');
  return out;
}

/** Decrypts a control record posted by `slot`, or returns null. The signature is for the caller to check. */
export function openControl(sodium: Sodium, key: Uint8Array, roomId: string, slot: number, bytes: Uint8Array): Opened<ControlRecord> | null {
  if (!validSlot(slot, 0) || bytes.length < 1 + NONCE_BYTES + TAG_BYTES || bytes.length > MAX_RECORD_BYTES || bytes[0] !== CONTROL_VERSION) return null;
  let plain: Uint8Array;
  try {
    plain = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, bytes.subarray(1 + NONCE_BYTES), controlAD(roomId, slot), bytes.subarray(1, 1 + NONCE_BYTES), key);
  } catch {
    return null;
  }
  const parts = unlayout(plain, RECORD_MIN_PADDED);
  plain.fill(0);
  if (!parts) return null;
  const v = parseJSON(parts.json);
  if (!validControl(v)) return null;
  return { record: v, signed: controlSigned(roomId, slot, parts.json), signature: parts.signature };
}

/**
 * Encrypts and signs one message with the chain's current key, then steps
 * the chain forward: the key that encrypted it is deleted at once.
 */
export function sealMessage(sodium: Sodium, chain: Chain, roomId: string, slot: number, signSecret: Uint8Array, record: MessageRecord): Uint8Array {
  if (!validMessage(record)) throw new Error('invalid message');
  if (chain.index >= MAX_COUNTER) throw new Error('chain exhausted');
  const { gen, index } = chain;
  const json = enc.encode(JSON.stringify(record));
  const plain = layout(json, sodium.crypto_sign_detached(messageSigned(roomId, slot, gen, index, json), signSecret), MESSAGE_MIN_PADDED);
  const mk = messageKey(sodium, chain.ck);
  advanceChain(sodium, chain, index + 1);
  const nonce = sodium.randombytes_buf(NONCE_BYTES);
  const ct = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(plain, messageAD(roomId, slot, gen, index), null, nonce, mk);
  sodium.memzero(mk);
  plain.fill(0);
  const out = new Uint8Array(MESSAGE_HEAD + ct.length + OUTER_SIG_BYTES);
  out[0] = MESSAGE_VERSION;
  const view = new DataView(out.buffer);
  view.setUint32(1, gen);
  view.setUint32(5, index);
  out.set(nonce, 9);
  out.set(ct, MESSAGE_HEAD);
  const body = out.subarray(0, out.length - OUTER_SIG_BYTES);
  out.set(sodium.crypto_sign_detached(outerSigned(roomId, slot, body), signSecret), out.length - OUTER_SIG_BYTES);
  if (out.length > MAX_RECORD_BYTES) throw new Error('record too large');
  return out;
}

function outerSigned(roomId: string, slot: number, body: Uint8Array): Uint8Array {
  return concat(enc.encode(`nullbin room message outer v1\0${roomId}\0${slot}\0`), body);
}

/** True if a message record carries its sender's outer signature (checked by every reader, before decrypting). */
export function checkOuterSignature(sodium: Sodium, signKey: Uint8Array, roomId: string, slot: number, bytes: Uint8Array): boolean {
  if (bytes.length < MESSAGE_HEAD + TAG_BYTES + OUTER_SIG_BYTES || bytes[0] !== MESSAGE_VERSION || signKey.length !== 32) return false;
  try {
    return sodium.crypto_sign_verify_detached(bytes.subarray(bytes.length - OUTER_SIG_BYTES), outerSigned(roomId, slot, bytes.subarray(0, bytes.length - OUTER_SIG_BYTES)), signKey);
  } catch {
    return false;
  }
}

/**
 * A commitment to a chain key at its place: every key delivery carries one,
 * so a sender cannot hand different members different chains for one
 * place without it showing. It reveals nothing about the key.
 */
export function chainCommit(sodium: Sodium, ck: Uint8Array, place: ChainPlace): string {
  return sodium.to_base64(sodium.crypto_generichash(16, enc.encode(`nullbin room chain commit v1 ${place.roomId} ${place.slot} ${place.gen} ${place.index}`), ck),
    sodium.base64_variants.URLSAFE_NO_PADDING);
}

/** A hash of a chat record's content, for receipts. */
export function contentHash(sodium: Sodium, record: MessageRecord): string {
  return sodium.to_base64(sodium.crypto_generichash(16, enc.encode(JSON.stringify(record)), null), sodium.base64_variants.URLSAFE_NO_PADDING);
}

// Names, labels and the room's name, padded to one size before encryption.
const NAME_PAD = 160;
const SEALED_NAME = /^[A-Za-z0-9_-]{299}$/; // crypto_box_seal of NAME_PAD bytes and a 16-byte binding
const BOXED_NAME = /^[A-Za-z0-9_-]{267}$/; // nonce || XChaCha20-Poly1305 of NAME_PAD bytes
const b64u = (sodium: Sodium, b: Uint8Array) => sodium.to_base64(b, sodium.base64_variants.URLSAFE_NO_PADDING);

function padName(name: string): Uint8Array {
  const b = enc.encode(name);
  if (b.length > NAME_PAD) throw new Error('name too long');
  const out = new Uint8Array(NAME_PAD);
  out.set(b);
  return out;
}

function unpadName(b: Uint8Array): string | null {
  let end = b.length;
  while (end > 0 && b[end - 1] === 0) end--;
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(b.subarray(0, end));
  } catch {
    return null;
  }
}

/** What a name, label or room name is, for the additional data that binds its ciphertext. */
export type NameKind = 'member' | 'label' | 'room';

function nameAD(roomId: string, kind: NameKind, slot: number): Uint8Array {
  return enc.encode(`nullbin room name v1 ${roomId} ${kind} ${slot}`);
}

/** Encrypts a name, label or room name under the roster key, bound to its room, kind and place. */
export function boxName(sodium: Sodium, rosterKey: Uint8Array, name: string, roomId: string, kind: NameKind, slot: number): string {
  const nonce = sodium.randombytes_buf(NONCE_BYTES);
  const plain = padName(name);
  const ct = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(plain, nameAD(roomId, kind, slot), null, nonce, rosterKey);
  return b64u(sodium, new Uint8Array([...nonce, ...ct]));
}

/** Decrypts boxName's output, or returns null. */
export function openBoxedName(sodium: Sodium, rosterKey: Uint8Array, boxed: string, roomId: string, kind: NameKind, slot: number): string | null {
  try {
    const b = sodium.from_base64(boxed, sodium.base64_variants.URLSAFE_NO_PADDING);
    const plain = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, b.subarray(NONCE_BYTES), nameAD(roomId, kind, slot), b.subarray(0, NONCE_BYTES), rosterKey);
    return unpadName(plain);
  } catch {
    return null;
  }
}

/** The join a sealed name belongs to: its room, place and keys. */
export interface NamePlace {
  roomId: string;
  slot: number;
  key: string;
  box: string;
}

function nameBinding(sodium: Sodium, p: NamePlace): Uint8Array {
  return sodium.crypto_generichash(16, enc.encode(`nullbin room sealed name v1 ${p.roomId} ${p.slot} ${p.key} ${p.box}`), null);
}

/**
 * Seals a joiner's name to the creator's name key, bound to their join:
 * only the creator reads it, to admit them, and nobody can copy it into
 * another join.
 */
export function sealName(sodium: Sodium, name: string, nameKey: Uint8Array, place: NamePlace): string {
  const plain = new Uint8Array(NAME_PAD + 16);
  plain.set(padName(name));
  plain.set(nameBinding(sodium, place), NAME_PAD);
  return b64u(sodium, sodium.crypto_box_seal(plain, nameKey));
}

/** Opens sealName's output with the creator's name key pair, for the join it must belong to, or returns null. */
export function openSealedName(sodium: Sodium, sealed: string, nameKey: Uint8Array, nameSecret: Uint8Array, place: NamePlace): string | null {
  try {
    const plain = sodium.crypto_box_seal_open(sodium.from_base64(sealed, sodium.base64_variants.URLSAFE_NO_PADDING), nameKey, nameSecret);
    if (plain.length !== NAME_PAD + 16 || !sodium.memcmp(plain.subarray(NAME_PAD), nameBinding(sodium, place))) return null;
    return unpadName(plain.subarray(0, NAME_PAD));
  } catch {
    return null;
  }
}

/** Seals the roster key to an admitted member's join key, bound to the room and their place. */
export function sealRoster(sodium: Sodium, rosterKey: Uint8Array, boxPublic: Uint8Array, roomId: string, slot: number): string {
  return sealChainKey(sodium, rosterKey, boxPublic, { roomId, slot: -1 - slot, gen: 0, index: 0 }, slot);
}

/** Opens sealRoster's output, or returns null. */
export function openRoster(sodium: Sodium, sealed: string, boxPublic: Uint8Array, boxSecret: Uint8Array, roomId: string, slot: number): Uint8Array | null {
  return openChainKey(sodium, sealed, boxPublic, boxSecret, { roomId, slot: -1 - slot, gen: 0, index: 0 }, slot);
}

/** True if a decrypted name or label follows the rules (cleanName and nameAllowed), up to `max` characters. */
export function validName(n: string | null, max: number, empty: boolean, room = false): n is string {
  return nameOk(n, max, empty, room);
}

/**
 * A short hash of a record's signature, for a tab to remember what it
 * posted: a control record's (over its content), a message's outer one
 * (over its bytes). Ed25519 signatures are deterministic, so re-encrypting
 * the same record, which anyone with the room key could do, keeps it; only
 * the signer's key makes a new one.
 */
export function signatureHash(sodium: Sodium, signature: Uint8Array): string {
  return sodium.to_base64(sodium.crypto_generichash(16, signature, null), sodium.base64_variants.URLSAFE_NO_PADDING);
}

/** The outer signature of a message record. */
export function outerSignature(bytes: Uint8Array): Uint8Array {
  return bytes.subarray(bytes.length - OUTER_SIG_BYTES);
}

/** The generation and index a message record claims, or null. */
export function messagePosition(bytes: Uint8Array): { gen: number; index: number } | null {
  if (bytes.length < MESSAGE_HEAD + TAG_BYTES + OUTER_SIG_BYTES || bytes.length > MAX_RECORD_BYTES || bytes[0] !== MESSAGE_VERSION) return null;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const gen = view.getUint32(1);
  const index = view.getUint32(5);
  return gen >= 1 && gen <= MAX_COUNTER && index <= MAX_COUNTER ? { gen, index } : null;
}

/**
 * Decrypts a message from `slot` with the reader's copy of that sender's
 * chain, and checks it is signed by the sender's signing key. Only then
 * does the chain step to just past this message (at most MAX_SKIP ahead),
 * deleting every key it passes, so a forged message cannot skip or destroy
 * a real one. Returns null if the message is from another generation,
 * already behind the chain, too far ahead, or not authentic; the chain is
 * then left unchanged.
 */
export function openMessage(sodium: Sodium, chain: Chain, roomId: string, slot: number, bytes: Uint8Array, signKey: Uint8Array): MessageRecord | null {
  const pos = messagePosition(bytes);
  if (!validSlot(slot, 0) || !pos || pos.gen !== chain.gen || pos.index < chain.index || pos.index - chain.index > MAX_SKIP) return null;
  if (!checkOuterSignature(sodium, signKey, roomId, slot, bytes)) return null;
  // Work on a copy, so a forged message cannot move the real chain.
  const trial: Chain = { gen: chain.gen, index: chain.index, ck: chain.ck.slice() };
  advanceChain(sodium, trial, pos.index);
  const mk = messageKey(sodium, trial.ck);
  let plain: Uint8Array;
  try {
    plain = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, bytes.subarray(MESSAGE_HEAD, bytes.length - OUTER_SIG_BYTES), messageAD(roomId, slot, pos.gen, pos.index), bytes.subarray(9, MESSAGE_HEAD), mk);
  } catch {
    sodium.memzero(mk);
    sodium.memzero(trial.ck);
    return null;
  } finally {
    sodium.memzero(mk);
  }
  const parts = unlayout(plain, MESSAGE_MIN_PADDED);
  plain.fill(0);
  const v = parts ? parseJSON(parts.json) : undefined;
  if (!parts || !validMessage(v) ||
    !verifySignature(sodium, { record: v, signed: messageSigned(roomId, slot, pos.gen, pos.index, parts.json), signature: parts.signature }, signKey)) {
    sodium.memzero(trial.ck);
    return null;
  }
  // Authentic: commit, stepping past this message's key.
  advanceChain(sodium, trial, pos.index + 1);
  sodium.memzero(chain.ck);
  chain.ck = trial.ck;
  chain.index = trial.index;
  return v;
}

/** Checks a record's signature against a member's public key. */
export function verifySignature(sodium: Sodium, opened: Opened<unknown>, publicKey: Uint8Array): boolean {
  try {
    return publicKey.length === 32 && sodium.crypto_sign_verify_detached(opened.signature, opened.signed, publicKey);
  } catch {
    return false;
  }
}

/** Where a sealed chain key belongs: its room, its sender and its position. */
export interface ChainPlace {
  roomId: string;
  slot: number;
  gen: number;
  index: number;
}

// Bound to the recipient's place too: a key sealed to one member cannot be
// presented as sealed to another, even if both used the same receiving key.
function binding(sodium: Sodium, p: ChainPlace, to: number): Uint8Array {
  return sodium.crypto_generichash(BINDING_BYTES, enc.encode(`nullbin room chain key v2 ${p.roomId} ${p.slot} ${p.gen} ${p.index} to ${to}`), null);
}

/** Seals a chain key, bound to its place and its recipient's place `to`, to one member's X25519 public key. */
export function sealChainKey(sodium: Sodium, ck: Uint8Array, boxPublic: Uint8Array, place: ChainPlace, to: number): string {
  const plain = new Uint8Array(32 + BINDING_BYTES);
  plain.set(ck);
  plain.set(binding(sodium, place, to), 32);
  try {
    return sodium.to_base64(sodium.crypto_box_seal(plain, boxPublic), sodium.base64_variants.URLSAFE_NO_PADDING);
  } finally {
    sodium.memzero(plain);
  }
}

/**
 * Opens a chain key sealed to us, or returns null. It must be bound to the
 * place the record carrying it claims: a member cannot hand on a chain key
 * someone else sealed to us as their own.
 */
export function openChainKey(sodium: Sodium, sealed: string, boxPublic: Uint8Array, boxSecret: Uint8Array, place: ChainPlace, to: number): Uint8Array | null {
  let plain: Uint8Array | null = null;
  try {
    const bytes = sodium.from_base64(sealed, sodium.base64_variants.URLSAFE_NO_PADDING);
    if (bytes.length !== SEALED_KEY_BYTES) return null;
    plain = sodium.crypto_box_seal_open(bytes, boxPublic, boxSecret);
    if (plain.length !== 32 + BINDING_BYTES || !sodium.memcmp(plain.subarray(32), binding(sodium, place, to))) return null;
    return plain.slice(0, 32);
  } catch {
    return null;
  } finally {
    if (plain) sodium.memzero(plain);
  }
}

// Any scalar works: libsodium clamps it, which multiplies by the cofactor.
const PROBE = new Uint8Array(32).fill(0x5a);

/**
 * True if an X25519 public key is usable: not one of the low-order points,
 * which crypto_box_seal refuses (one member announcing such a key would
 * otherwise stop everyone's key deliveries).
 */
export function boxKeyOk(sodium: Sodium, key: Uint8Array): boolean {
  if (key.length !== 32) return false;
  try {
    const shared = sodium.crypto_scalarmult(PROBE, key);
    const zero = shared.every((b) => b === 0);
    sodium.memzero(shared);
    return !zero;
  } catch {
    return false;
  }
}

/** Decodes a 32-byte public key from canonical base64url, or returns null. */
export function decodeKey(sodium: Sodium, key: string): Uint8Array | null {
  if (!B64URL_32.test(key)) return null;
  try {
    const b = sodium.from_base64(key, sodium.base64_variants.URLSAFE_NO_PADDING);
    return b.length === 32 && sodium.to_base64(b, sodium.base64_variants.URLSAFE_NO_PADDING) === key ? b : null;
  } catch {
    return null;
  }
}

export function encodeKey(sodium: Sodium, key: Uint8Array): string {
  return sodium.to_base64(key, sodium.base64_variants.URLSAFE_NO_PADDING);
}

/**
 * Proof that a join comes from someone holding the invite link for its
 * place: a keyed BLAKE2b hash, under the invite's secret (which only the
 * link and the creator's tab hold, never the server), of the room, the
 * place and the joiner's keys. The creator admits only joins with a valid
 * proof, so the room key alone cannot take an invited place.
 */
export function joinProof(sodium: Sodium, secret: Uint8Array, roomId: string, slot: number, key: string, box: string, password: Uint8Array | null = null): string {
  return encodeKey(sodium, proofHash(sodium, secret, roomId, slot, key, box, password));
}

/**
 * The proof's hash. In a room with a password, it is keyed by the invite's
 * secret and the password key together, under its own label: the link
 * alone (or the password alone) proves nothing.
 */
function proofHash(sodium: Sodium, secret: Uint8Array, roomId: string, slot: number, key: string, box: string, password: Uint8Array | null): Uint8Array {
  if (password === null) return sodium.crypto_generichash(32, enc.encode(`nullbin room join v1 ${roomId} ${slot} ${key} ${box}`), secret);
  if (secret.length !== 32 || password.length !== 32) throw new Error('bad proof key');
  const both = new Uint8Array(64);
  both.set(secret, 0);
  both.set(password, 32);
  try {
    return sodium.crypto_generichash(32, enc.encode(`nullbin room join v2 ${roomId} ${slot} ${key} ${box}`), both);
  } finally {
    sodium.memzero(both);
  }
}

/**
 * The room's password key: Argon2id (the paste passwords' parameters) of
 * the password, salted by the room. Only the creator's tab and joiners hold
 * it, never the server or a link. It enters only join proofs, which are
 * sealed to nobody: an offline guess needs a proof, the link it was made
 * with, and Argon2id per guess (THREAT_MODEL.md R25).
 */
export function roomPasswordKey(sodium: Sodium, password: string, roomId: string): Uint8Array {
  const pw = sodium.from_string(password.normalize('NFC'));
  if (pw.length === 0 || pw.length > MAX_ROOM_PASSWORD_BYTES) {
    sodium.memzero(pw);
    throw new Error('bad password length');
  }
  const salt = sodium.crypto_generichash(sodium.crypto_pwhash_SALTBYTES, enc.encode(`nullbin room password salt v1 ${roomId}`), null);
  try {
    return sodium.crypto_pwhash(32, pw, salt, sodium.crypto_pwhash_OPSLIMIT_MODERATE, sodium.crypto_pwhash_MEMLIMIT_MODERATE, sodium.crypto_pwhash_ALG_ARGON2ID13);
  } finally {
    sodium.memzero(pw);
  }
}

/**
 * What the creator's signed invite record says about the link's secret, so
 * the person who uses the link can tell if it was changed on the way (a
 * changed secret makes a proof the creator refuses). It shows nothing of
 * the secret.
 */
export function inviteCheck(sodium: Sodium, secret: Uint8Array, roomId: string, slot: number): string {
  return encodeKey(sodium, sodium.crypto_generichash(32, enc.encode(`nullbin room invite check v1 ${roomId} ${slot}`), secret));
}

/** Checks a join's proof in constant time. */
export function checkJoinProof(sodium: Sodium, secret: Uint8Array, roomId: string, slot: number, key: string, box: string, proof: string, password: Uint8Array | null = null): boolean {
  const got = decodeKey(sodium, proof);
  if (!got) return false;
  const want = proofHash(sodium, secret, roomId, slot, key, box, password);
  try {
    return sodium.memcmp(got, want);
  } finally {
    sodium.memzero(want);
  }
}

/**
 * A code for comparing a member's identity in person: 30 digits (about 99
 * bits) from a hash of their signing key, which signs everything else they
 * announce. Everyone sees the same code for the same member.
 */
export function safetyCode(sodium: Sodium, signKey: Uint8Array): string {
  const h = sodium.crypto_generichash(32, signKey, enc.encode('nullbin room safety code v2'));
  const view = new DataView(h.buffer, h.byteOffset, h.byteLength);
  const groups: string[] = [];
  for (let i = 0; i < 6; i++) groups.push(String(view.getUint32(i * 4) % 100000).padStart(5, '0'));
  return groups.join(' ');
}

function validSlot(n: unknown, min: number): n is number {
  return typeof n === 'number' && Number.isInteger(n) && n >= min && n < MAX_SLOTS;
}

function plainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v) && Object.getPrototypeOf(v) === Object.prototype;
}

function common(o: Record<string, unknown>, keys: string): boolean {
  const { id, time } = o;
  return Object.keys(o).sort().join(',') === keys &&
    typeof id === 'string' && ID.test(id) &&
    typeof time === 'number' && Number.isSafeInteger(time) && time > 0 && time <= MAX_TIME;
}

// Letters from other scripts that look like Latin ones, for comparing names.
const LOOKALIKES: Record<string, string> = {
  'а': 'a', 'в': 'b', 'е': 'e', 'ё': 'e', 'з': '3', 'і': 'i', 'ї': 'i', 'ј': 'j', 'к': 'k', 'м': 'm', 'н': 'h', 'о': 'o', 'п': 'n',
  'р': 'p', 'с': 'c', 'т': 't', 'у': 'y', 'х': 'x', 'ѕ': 's', 'ԁ': 'd', 'ӏ': 'l', 'һ': 'h', 'ԛ': 'q', 'ԝ': 'w', 'ү': 'y', 'ɡ': 'g',
  'α': 'a', 'β': 'b', 'γ': 'y', 'ε': 'e', 'η': 'n', 'ι': 'i', 'κ': 'k', 'ν': 'v', 'ο': 'o', 'ρ': 'p', 'τ': 't', 'υ': 'u', 'χ': 'x',
  'ω': 'w', 'ɑ': 'a', 'ı': 'i', 'ȷ': 'j', 'ℓ': 'l', '0': 'o', '1': 'l', '|': 'l',
  // Latin small capitals and phonetic letters, which compatibility
  // normalization leaves alone ("ꜱᴀᴍ" for "sam", "ʏᴏᴜ" for "you").
  'ᴀ': 'a', 'ʙ': 'b', 'ᴄ': 'c', 'ᴅ': 'd', 'ᴇ': 'e', 'ꜰ': 'f', 'ɢ': 'g', 'ʜ': 'h', 'ɪ': 'i', 'ᴊ': 'j', 'ᴋ': 'k', 'ʟ': 'l', 'ᴍ': 'm',
  'ɴ': 'n', 'ᴏ': 'o', 'ᴘ': 'p', 'ꞯ': 'q', 'ʀ': 'r', 'ꜱ': 's', 'ᴛ': 't', 'ᴜ': 'u', 'ᴠ': 'v', 'ᴡ': 'w', 'ʏ': 'y', 'ᴢ': 'z',
  'ɛ': 'e', 'ɩ': 'i', 'ʋ': 'v', 'ɐ': 'a', 'ɔ': 'c', 'ɾ': 'r', 'ʂ': 's', 'ƽ': 's',
};

/**
 * How a name looks, roughly: compatibility-normalized, without marks,
 * invisible characters and spaces, in lower case, with lookalike letters
 * folded together. Two names with the same skeleton could pass for each
 * other.
 */
export function nameSkeleton(name: string): string {
  const plain = name.normalize('NFKD').replace(/[\p{M}\p{Cf}\p{Z}\s\u034F\u115F\u1160\u3164\uFE00-\uFE0F]/gu, '').toLowerCase();
  // I, l, i, 1 and | look alike in many fonts, as do rn and m, vv and w.
  // Punctuation and symbols are dropped: "Sam." passes for "Sam".
  return Array.from(plain, (c) => LOOKALIKES[c] ?? c).join('')
    .replace(/i/g, 'l').replace(/rn/g, 'm').replace(/vv/g, 'w').replace(/[^\p{L}\p{N}]/gu, '');
}

/** The words of a name, folded like a skeleton: "Ada (you)" has "ada" and "you". */
export function nameWords(name: string): string[] {
  const plain = name.normalize('NFKD').replace(/[\p{M}\p{Cf}\p{Cn}\p{Co}\p{Cs}\p{Default_Ignorable_Code_Point}\u034F\uFE00-\uFE0F]/gu, '').toLowerCase();
  return Array.from(plain, (c) => LOOKALIKES[c] ?? c).join('').split(/[^\p{L}\p{N}]+/u).filter(Boolean);
}

/** A name's words without digits, folded like a skeleton: "Admin2" has "admln". */
export function nameStems(name: string): string[] {
  return nameWords(name).map((w) => w.replace(/\p{N}/gu, '').replace(/i/g, 'l').replace(/rn/g, 'm')).filter(Boolean);
}

/**
 * Rules for names, labels and (with `room`) the room's name beyond
 * cleanName: no stacks of more than three combining marks (they draw over
 * other text); and for people's names and labels, nothing that could pass
 * for the code badge or the verified mark the app adds (more than four
 * digits, digits in brackets as in "Sam (12345)", check marks, "verified").
 */
export function nameAllowed(n: string, room = false): boolean {
  const plain = n.normalize('NFKD');
  // Something visible: a name of joiners or marks alone shows as nothing.
  if (n !== '' && !/[\p{L}\p{N}\p{Extended_Pictographic}]/u.test(plain)) return false;
  // No more than three marks stacked on one character (full Hebrew
  // pointing has three).
  if (STACKS(4).test(plain)) return false;
  // The room's name never sits next to a code; people's names and invite
  // labels hold at most four digits of any kind, none in brackets (the
  // codes the app shows have ten or thirty).
  if (room) return true;
  const skeleton = nameSkeleton(n);
  return !/[\p{Ps}<][^\p{Pe}>]*\p{N}/u.test(plain) &&
    (plain.match(/\p{N}/gu)?.length ?? 0) <= 4 &&
    // Nor a check mark or the word "verified", even in lookalike letters,
    // which show members you verified.
    !/[\u2713\u2714\u2611\u2705\u221A\u237B\u2E3A\u{1F5F8}\u{1F5F9}\u{10102}]/u.test(plain) &&
    !/verif/iu.test(plain.replace(/[^\p{L}]/gu, '')) && !skeleton.includes('verlf') &&
    // Nor what the app calls people with no name yet ("The creator",
    // "Member 3"), nor a role the room does not have.
    // Anything that starts like them counts ("The creator2", "Member 3x"),
    // and digits do not hide a role ("Admin2", "0wner").
    !skeleton.startsWith('thecreator') && !/^member(?:[\p{N}ol].*)?$/u.test(skeleton) &&
    !nameStems(n).some((w) => ROLE_WORDS.has(w));
}

/** Roles a name or label could claim (folded like a skeleton); a room has only its creator and members. */
const ROLE_WORDS = new Set(['creator', 'admln', 'admlnlstrator', 'owner', 'mod', 'moderator', 'support', 'staff', 'offlclal', 'system', 'nullbln', 'host']);

const nameOk = (n: unknown, max: number, empty: boolean, room = false) => typeof n === 'string' && n.length <= max && (empty || n.length > 0) && cleanName(n) === n && nameAllowed(n, room);
const counter = (n: unknown, min: number) => typeof n === 'number' && Number.isInteger(n) && n >= min && n <= MAX_COUNTER;

/** The exact schema of every control record. */
export function validControl(v: unknown): v is ControlRecord {
  if (!plainObject(v)) return false;
  switch (v['t']) {
    case 'room':
      return common(v, 'ends,id,max,name,pw,t,time,ttl') && typeof v['name'] === 'string' && BOXED_NAME.test(v['name']) &&
        typeof v['ends'] === 'number' && Number.isSafeInteger(v['ends']) && v['ends'] > 0 && v['ends'] <= MAX_TIME &&
        typeof v['pw'] === 'boolean' && typeof v['max'] === 'number' && Number.isInteger(v['max']) && v['max'] >= MIN_MEMBERS && v['max'] <= MAX_SLOTS &&
        typeof v['ttl'] === 'number' && INVITE_TTLS.includes(v['ttl']);
    case 'join':
      // The creator's join carries its name boxed and its name key; any
      // other, its name sealed to that key and (for invited places) a proof.
      return ((common(v, 'box,id,key,name,namekey,t,time') && typeof v['namekey'] === 'string' && B64URL_32.test(v['namekey']) &&
          typeof v['name'] === 'string' && BOXED_NAME.test(v['name'])) ||
        ((common(v, 'box,id,key,name,t,time') || (common(v, 'box,id,key,name,proof,t,time') && typeof v['proof'] === 'string' && B64URL_32.test(v['proof']))) &&
          typeof v['name'] === 'string' && SEALED_NAME.test(v['name']))) &&
        typeof v['key'] === 'string' && B64URL_32.test(v['key']) && typeof v['box'] === 'string' && B64URL_32.test(v['box']);
    case 'invite':
      return common(v, 'check,exp,id,label,slot,t,time') && validSlot(v['slot'], 1) && typeof v['label'] === 'string' && BOXED_NAME.test(v['label']) &&
        typeof v['check'] === 'string' && B64URL_32.test(v['check']) && typeof v['exp'] === 'number' && Number.isSafeInteger(v['exp']) && v['exp'] > 0 && v['exp'] <= MAX_TIME;
    case 'remove':
      return common(v, 'id,slot,t,time') && validSlot(v['slot'], 1);
    case 'admit':
      return common(v, 'id,key,name,roster,slot,t,time') && validSlot(v['slot'], 1) && typeof v['key'] === 'string' && B64URL_32.test(v['key']) &&
        typeof v['roster'] === 'string' && B64URL_SEALED.test(v['roster']) && typeof v['name'] === 'string' && BOXED_NAME.test(v['name']);
    case 'keys': {
      const to = v['to'];
      if (!common(v, 'commit,gen,id,index,t,time,to') || !counter(v['gen'], 1) || !counter(v['index'], 0) ||
        typeof v['commit'] !== 'string' || !B64URL_16.test(v['commit'])) return false;
      if (!Array.isArray(to) || to.length < 1 || to.length >= MAX_SLOTS) return false;
      const slots = new Set<number>();
      for (const e of to) {
        if (!plainObject(e) || Object.keys(e).sort().join(',') !== 'box,n,slot' || !validSlot(e['slot'], 0) || slots.has(e['slot']) ||
          !counter(e['n'], 0) || typeof e['box'] !== 'string' || !B64URL_SEALED.test(e['box'])) return false;
        slots.add(e['slot']);
      }
      return true;
    }
    case 'box':
      return common(v, 'box,id,n,t,time') && counter(v['n'], 1) && (v['n'] as number) <= MAX_BOX_N && typeof v['box'] === 'string' && B64URL_32.test(v['box']);
    default:
      return false;
  }
}

const FLAG_HOLD = '\uE000'; // stands in for a flag (FLAG_TAGS) while text is cleaned
// Marks that stack on one character: nonspacing and enclosing ones, but not
// Tibetan subjoined letters, which stack downwards as letters do.
const STACKS = (n: number) => new RegExp(`(?:(?![\\u0F90-\\u0FBC])[\\p{Mn}\\p{Me}]){${n},}`, 'u');
const TOO_TALL = STACKS(6);
// More than two blank (or blank-looking) lines in a row.
const TOO_BLANK = /\n(?:(?:(?!\n)[\s\u2800])*\n){3,}/u;

function textSafe(t: string): boolean {
  // The private character cleanText uses for flags never comes in.
  if (t.includes(FLAG_HOLD)) return false;
  const s = t.replace(FLAG_TAGS, '\u{1F3F4}');
  // Tabs and line breaks are the only control characters allowed.
  if (HIDDEN.test(s.replace(/[\t\n]/g, ''))) return false;
  const cps = Array.from(s);
  for (let i = 0; i < cps.length; i++) {
    if ('\u200C\u200D\uFE0E\uFE0F'.includes(cps[i]!) && !joinerOk(cps, i)) return false;
  }
  return !TOO_TALL.test(s.replace(/[\u200C\u200D]/g, '')) && !TOO_BLANK.test(s);
}

/**
 * Makes message text safe to send: line separators become line breaks,
 * hidden characters and stray joiners go, stacks of more than five marks
 * and runs of blank lines shrink, blank lines at the start and spaces at
 * line ends go. Receivers refuse text this would change.
 */
export function cleanText(text: string): string {
  const flags: string[] = [];
  let t = text.replaceAll(FLAG_HOLD, '').replace(FLAG_TAGS, (f) => {
    flags.push(f);
    return FLAG_HOLD;
  }).replace(/\r\n?|[\u2028\u2029]/g, '\n');
  for (let round = 0; round < 4; round++) {
    let cps = Array.from(t).filter((c) => c === '\t' || c === '\n' || !HIDDEN.test(c));
    cps = cps.filter((c, i) => !'\u200C\u200D\uFE0E\uFE0F'.includes(c) || joinerOk(cps, i));
    t = cps.join('');
    // Shorten stacks of marks to five.
    let run = 0;
    t = Array.from(t).filter((c) => {
      if (/[\p{Mn}\p{Me}]/u.test(c) && !/[\u0F90-\u0FBC]/u.test(c)) return ++run <= 5;
      if (c !== '\u200C' && c !== '\u200D') run = 0;
      return true;
    }).join('');
    t = t.replace(/[^\S\n]+\n/g, '\n')
      .replace(/\n(?:(?:(?!\n)[\s\u2800])*\n){3,}/gu, '\n\n\n')
      .replace(/^(?:(?:(?!\n)[\s\u2800])*\n)+/u, '')
      .trimEnd();
    if (textSafe(t.replaceAll(FLAG_HOLD, '\u{1F3F4}'))) break;
  }
  let k = 0;
  t = t.replaceAll(FLAG_HOLD, () => flags[k++] ?? '');
  return visible(t) && textSafe(t) ? t : '';
}

// Something that shows: not just spaces, blank braille or marks.
const visible = (t: string) => /[^\p{Z}\s\u2800\p{M}]/u.test(t);
// Indentation on the first line is kept; blank lines at the start and
// spaces at the end are not.
const textOk = (t: unknown) => typeof t === 'string' && t.length > 0 && t.length <= MAX_MESSAGE_LENGTH && t.trimEnd() === t && visible(t) &&
  !/^(?:(?:(?!\n)[\s\u2800])*\n)/u.test(t) && textSafe(t);
const idOk = (t: unknown) => typeof t === 'string' && ID.test(t);
const refOk = (r: unknown) => plainObject(r) && Object.keys(r).sort().join(',') === 'author,id' && idOk(r['id']) && validSlot(r['author'], 0);
// Receipts: exactly one per place, in order, so a message's size does not
// show how much its sender read (generation 0 means nothing read there).
const acksOk = (a: unknown) => {
  if (!Array.isArray(a) || a.length !== MAX_SLOTS) return false;
  return a.every((e, i) => plainObject(e) && Object.keys(e).sort().join(',') === 'gen,h,index,slot' && e['slot'] === i &&
    counter(e['gen'], 0) && counter(e['index'], 0) && typeof e['h'] === 'string' && B64URL_16.test(e['h']) &&
    (e['gen'] !== 0 || (e['index'] === 0 && e['h'] === NO_ACK)));
};
/** The hash in a receipt for a place we read nothing from. */
export const NO_ACK = 'A'.repeat(22);

const prevOk = (p: unknown) => p === null || (plainObject(p) && Object.keys(p).sort().join(',') === 'gen,h,index' &&
  counter(p['gen'], 1) && counter(p['index'], 0) && typeof p['h'] === 'string' && B64URL_16.test(p['h']) && p['h'] !== NO_ACK);

const MAX_CHAT_FILE_SIZE = 2 * 1024 * 1024 * 1024; // HardMaxSize (2 GiB)

/**
 * Sanitizes a filename for Null Chat file cards so it always satisfies
 * cleanFileName, hasHiddenChars (including PUA/surrogates), and the 255 UTF-16
 * code-unit cap.
 */
export function cleanChatFileName(name: string): string {
  // Strip Private Use Area and lone surrogates that hasHiddenChars flags,
  // then apply cleanFileName and cap at 255 UTF-16 code units without
  // splitting a surrogate pair.
  const stripped = name.replace(/[\p{Co}\p{Cs}]/gu, '_');
  let cleaned = cleanFileName(stripped, 'file');
  if (cleaned.length > 255) {
    let end = 255;
    if (/[\uD800-\uDBFF]/.test(cleaned[end - 1]!)) end--;
    cleaned = cleanFileName(cleaned.slice(0, end), 'file');
  }
  return !hasHiddenChars(cleaned) && cleaned.length > 0 && cleaned.length <= 255 ? cleaned : 'file';
}

const fileOk = (f: unknown): f is ChatFile =>
  plainObject(f) && Object.keys(f).sort().join(',') === 'id,key,name,size' &&
  idOk(f['id']) && typeof f['key'] === 'string' && B64URL_32.test(f['key']) &&
  typeof f['name'] === 'string' && f['name'].length > 0 && f['name'].length <= 255 &&
  cleanChatFileName(f['name']) === f['name'] && !hasHiddenChars(f['name']) &&
  typeof f['size'] === 'number' && Number.isSafeInteger(f['size']) && f['size'] >= 0 && f['size'] <= MAX_CHAT_FILE_SIZE;

/** The exact schema of every chat record. */
export function validMessage(v: unknown): v is MessageRecord {
  if (!plainObject(v)) return false;
  switch (v['t']) {
    case 'msg': {
      const hasFile = 'file' in v;
      if (!common(v, hasFile ? 'file,id,prev,reply,seen,t,text,time' : 'id,prev,reply,seen,t,text,time')) return false;
      if (hasFile && !fileOk(v['file'])) return false;
      const textValid = hasFile && v['text'] === '' ? true : textOk(v['text']);
      return textValid && prevOk(v['prev']) && (v['reply'] === null || refOk(v['reply'])) && acksOk(v['seen']);
    }
    case 'react':
      return common(v, 'author,emoji,id,on,prev,t,target,time') && prevOk(v['prev']) && idOk(v['target']) && validSlot(v['author'], 0) &&
        typeof v['emoji'] === 'string' && REACTIONS.includes(v['emoji']) && typeof v['on'] === 'boolean';
    case 'edit':
      return common(v, 'id,prev,t,target,text,time') && prevOk(v['prev']) && idOk(v['target']) && textOk(v['text']);
    case 'unsend':
      return common(v, 'id,prev,t,target,time') && prevOk(v['prev']) && idOk(v['target']);
    case 'seen':
      return common(v, 'id,prev,seen,t,time') && prevOk(v['prev']) && acksOk(v['seen']);
    default:
      return false;
  }
}
