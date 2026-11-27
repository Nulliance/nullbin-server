// Seals chat records as an honest app does: each commits to its sender's
// previous record (its place and content hash). Tests that play a sender
// call this instead of sealMessage, so a record's prev is right without
// every test working it out. History is kept per signing key: records
// sealed at one place on two copies of a chain (a split) both commit to
// the same previous record, as a real split would.
import { contentHash, sealMessage, type Chain, type MessageRecord, type Prev } from '../src/room-crypto.ts';
import type { Sodium } from '../src/sodium.ts';

const history = new WeakMap<Uint8Array, Map<string, string>>();

/** The record a sender's record at (gen, index) commits to, from what that key sealed before. */
export function prevFor(signSecret: Uint8Array, gen: number, index: number): Prev | null {
  const past = history.get(signSecret);
  if (!past) return null;
  if (index > 0) {
    const h = past.get(`${gen}:${index - 1}`);
    return h === undefined ? null : { gen, index: index - 1, h };
  }
  let best: Prev | null = null;
  for (const [k, h] of past) {
    const [g, i] = k.split(':').map(Number) as [number, number];
    if (g < gen && (!best || g > best.gen || (g === best.gen && i > best.index))) best = { gen: g, index: i, h };
  }
  return best;
}

/** sealMessage, with record.prev set (in place) to the sender's previous record. */
export function sealChained(sodium: Sodium, chain: Chain, roomId: string, slot: number, signSecret: Uint8Array, record: MessageRecord): Uint8Array {
  const { gen, index } = chain;
  record.prev = prevFor(signSecret, gen, index);
  const out = sealMessage(sodium, chain, roomId, slot, signSecret, record);
  let past = history.get(signSecret);
  if (!past) {
    past = new Map();
    history.set(signSecret, past);
  }
  past.set(`${gen}:${index}`, contentHash(sodium, record));
  return out;
}
