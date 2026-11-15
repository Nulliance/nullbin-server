// URL fragments. The fragment is never sent to the server by browsers.
//
//   view link:   /p/<id>#<key>      or /p/<id>#<key>.b  (.b = burn after reading)
//   recipient:   /p/<id>#<key>.r<secret> or /p/<id>#<key>.b.r<secret>
//                (one of a paste's separate links; .b = it has an open limit)
//   delete link: /d/<id>#d.<delete token>, or #d.<delete token>.r for a
//                paste with separate links (its page then lists them)
//
// Keys and delete tokens are both 43 random base64url characters. The "d."
// marks a delete token, so a view link edited to /d/ can never send its key
// to the server as a delete token.

import type { Sodium } from './sodium.ts';
import { KEY_BYTES } from './format.ts';

const B64URL_32_BYTES = /^[A-Za-z0-9_-]{43}$/;
const B64URL_16_BYTES = /^[A-Za-z0-9_-]{22}$/;
const RECIPIENT_SECRET_BYTES = 16;

export function encodeKeyFragment(sodium: Sodium, key: Uint8Array, burn: boolean, recipient: Uint8Array | null = null): string {
  if (key.length !== KEY_BYTES) throw new Error('bad key length');
  if (recipient !== null && recipient.length !== RECIPIENT_SECRET_BYTES) throw new Error('bad recipient secret');
  let f = sodium.to_base64(key, sodium.base64_variants.URLSAFE_NO_PADDING);
  if (burn) f += '.b';
  if (recipient !== null) f += `.r${sodium.to_base64(recipient, sodium.base64_variants.URLSAFE_NO_PADDING)}`;
  return f;
}

export interface KeyFragment {
  key: Uint8Array;
  /** The link has an open limit (for a recipient link: its own). */
  burn: boolean;
  /** The secret of one of the paste's separate recipient links, or null. */
  recipient: Uint8Array | null;
}

/** Decodes canonical unpadded base64url of exactly `bytes` bytes, or returns null. */
function decodeExact(sodium: Sodium, s: string, bytes: number): Uint8Array | null {
  let out: Uint8Array;
  try {
    out = sodium.from_base64(s, sodium.base64_variants.URLSAFE_NO_PADDING);
  } catch {
    return null;
  }
  // Reject non-canonical encodings (stray bits in the last character).
  return out.length === bytes && sodium.to_base64(out, sodium.base64_variants.URLSAFE_NO_PADDING) === s ? out : null;
}

/**
 * Parses "#<key>", "#<key>.b", "#<key>.r<secret>" or "#<key>.b.r<secret>".
 * Returns null for anything else.
 */
export function parseKeyFragment(sodium: Sodium, fragment: string): KeyFragment | null {
  const f = fragment.startsWith('#') ? fragment.slice(1) : fragment;
  const parts = f.split('.');
  const k = parts.shift() ?? '';
  let burn = false;
  if (parts[0] === 'b') {
    burn = true;
    parts.shift();
  }
  let secret: string | null = null;
  if (parts.length > 0 && parts[0]!.startsWith('r')) secret = parts.shift()!.slice(1);
  if (parts.length > 0 || !B64URL_32_BYTES.test(k) || (secret !== null && !B64URL_16_BYTES.test(secret))) return null;
  const key = decodeExact(sodium, k, KEY_BYTES);
  if (!key) return null;
  let recipient: Uint8Array | null = null;
  if (secret !== null) {
    recipient = decodeExact(sodium, secret, RECIPIENT_SECRET_BYTES);
    if (!recipient) {
      sodium.memzero(key);
      return null;
    }
  }
  return { key, burn, recipient };
}

/** The fragment of a delete link, without the "#". */
export function encodeTokenFragment(token: string, recipients = false): string {
  if (!B64URL_32_BYTES.test(token)) throw new Error('bad delete token');
  return recipients ? `d.${token}.r` : `d.${token}`;
}

/** Parses "#d.<delete token>". The token is opaque: 43 base64url characters. */
export function parseTokenFragment(fragment: string): string | null {
  return parseDeleteFragment(fragment)?.token ?? null;
}

/** Parses "#d.<delete token>" or "#d.<delete token>.r" (the paste has separate links). */
export function parseDeleteFragment(fragment: string): { token: string; recipients: boolean } | null {
  const f = fragment.startsWith('#') ? fragment.slice(1) : fragment;
  if (!f.startsWith('d.')) return null;
  const recipients = f.endsWith('.r');
  const token = f.slice(2, recipients ? -2 : undefined);
  return B64URL_32_BYTES.test(token) ? { token, recipients } : null;
}

//   room invite: /r/<id>#<room key>.i<invite token>.c<creator key>.s<invite secret>.n<place>
// The room key, the creator's key and the invite secret never reach the
// server; the invite token is sent once, to join.

/** The fragment of a room invite, without the "#". */
export function encodeInviteFragment(sodium: Sodium, roomKey: Uint8Array, inviteToken: string, creatorKey: Uint8Array, secret: Uint8Array, slot: number): string {
  if (roomKey.length !== KEY_BYTES || creatorKey.length !== KEY_BYTES || secret.length !== KEY_BYTES || !B64URL_32_BYTES.test(inviteToken) ||
    !Number.isInteger(slot) || slot < 1 || slot > 19) throw new Error('bad invite');
  const b = (x: Uint8Array) => sodium.to_base64(x, sodium.base64_variants.URLSAFE_NO_PADDING);
  return `${b(roomKey)}.i${inviteToken}.c${b(creatorKey)}.s${b(secret)}.n${slot}`;
}

/**
 * Parses "#<room key>.i<invite token>.c<creator's signing key>.s<invite
 * secret>.n<place>". The creator's key lets the joiner check who created
 * the room; the invite secret proves to the creator that a join came from
 * this link; the place lets the joiner check that the server put them where
 * the invite was made for. Returns null for anything else.
 */
export function parseInviteFragment(sodium: Sodium, fragment: string): { key: Uint8Array; invite: string; creator: Uint8Array; secret: Uint8Array; slot: number } | null {
  const f = fragment.startsWith('#') ? fragment.slice(1) : fragment;
  const m = /^([A-Za-z0-9_-]{43})\.i([A-Za-z0-9_-]{43})\.c([A-Za-z0-9_-]{43})\.s([A-Za-z0-9_-]{43})\.n([1-9]|1[0-9])$/.exec(f);
  if (!m) return null;
  const key = decodeExact(sodium, m[1]!, KEY_BYTES);
  const creator = decodeExact(sodium, m[3]!, KEY_BYTES);
  const secret = decodeExact(sodium, m[4]!, KEY_BYTES);
  return key && creator && secret ? { key, invite: m[2]!, creator, secret, slot: Number(m[5]) } : null;
}
