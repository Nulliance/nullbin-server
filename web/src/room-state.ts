// The state of a burner room, rebuilt from its records in server order.
// Pure logic, no DOM: every rule about which records to trust lives here.
//
// - A slot's identity is a join record signed with the signing key it
//   announces (along with its X25519 key). The creator (slot 0) is trusted
//   on its first join, which must match the creator key in the invite link.
//   Anyone else becomes a member only once the creator's signed "admit"
//   record names their signing key: the room key alone (which every invite
//   link carries, used or not) cannot add a member, even with the server's
//   help. Later joins for a slot are ignored, so nobody can replace a
//   member's keys.
// - What this tab already knew (the creator's key, admitted members,
//   removals) is pinned: a history that contradicts it is flagged.
// - Every other record must be signed by its slot's signing key, so it needs
//   that member's secret key, not just the room key.
// - Only slot 0 (the creator) may name the room, label invites and announce
//   removals.
// - A sender's chain key reaches us in a "keys" record sealed to one of our
//   numbered X25519 receiving keys. We only ever move a chain forward (a
//   newer generation, or a later index), so a replayed delivery cannot bring
//   back deleted keys. Members announce new receiving keys in signed "box"
//   records; their numbers only go up.
// - Our own messages come back from the server unreadable to us (we deleted
//   their keys when sending); the page shows them when it sends them.
// - Records are deduplicated by sender and random id, so a replay shows
//   once. Replies and reactions name the message's sender as well as its
//   id, so nobody can stand in for someone else's message by reusing its id.

import type { Sodium } from './sodium.ts';
import {
  CONTROL_VERSION,
  MAX_NAME_LENGTH,
  MAX_ROOM_NAME_LENGTH,
  MAX_SLOTS,
  MAX_SKIP,
  MESSAGE_VERSION,
  advanceChain,
  boxKeyOk,
  chainCommit,
  contentHash,
  checkOuterSignature,
  decodeKey,
  messagePosition,
  NO_ACK,
  outerSignature,
  signatureHash,
  openBoxedName,
  openChainKey,
  openControl,
  openMessage,
  openRoster,
  openSealedName,
  validName,
  nameSkeleton,
  nameWords,
  safetyCode,
  verifySignature,
  type Chain,
  type Ack,
  type MessageRecord,
  type Ref,
} from './room-crypto.ts';

export { nameSkeleton };

export interface Member {
  slot: number;
  name: string;
  signKey: Uint8Array;
  /** Their current receiving key, and its number. */
  boxKey: Uint8Array;
  boxN: number;
  code: string;
  removed: boolean;
  /** Their join record's keys and invite proof, as posted. */
  join: { key: string; box: string; proof: string | null };
  /** When they joined, by their own clock (signed). */
  joinedAt: number;
}

export interface Message {
  id: string;
  /** Sender and id together: ids are unique per sender only. */
  key: string;
  from: number;
  text: string;
  time: number;
  reply: Ref | null;
  /**
   * What a reply quotes, fixed when the reply arrived: the message it
   * answers and its text then, or null text if we did not have it.
   */
  quote: { author: number; text: string | null; target: Message | null } | null;
  edited: boolean;
  /** Unsent by its sender: its text is gone. */
  deleted: boolean;
  /** Who reacted with what. */
  reactions: Map<string, Set<number>>;
}

/** A receiving key pair of ours. */
export interface BoxKey {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

/** What this tab already knew about the room, kept across reloads. */
export interface Pins {
  /** Signing keys by slot: the creator's (from the invite link) and admitted members'. */
  known?: Map<number, Uint8Array>;
  /** Slots removed from the room. */
  removed?: Iterable<number>;
  /** The newest receiving key seen for each slot, by number: a history without it cannot roll it back. */
  boxes?: Map<number, { n: number; key: Uint8Array }>;
}

/** Joins kept per slot while waiting for the creator's admit. */
const MAX_WAITING = 64;
/** How far a member's receiving-key number may move in one record (the server may hide a few). */
const MAX_BOX_STEP = 64;
/** A delivery sealed to a receiving key replaced this long before it was sent means someone was shown an old key. */
const STALE_KEY_MS = 10 * 60_000;

/** The words of a name folded like a skeleton, with digits split from letters: "Sam2 (work)" has "sam", "2" and "work". */
function nameTokens(name: string): string[] {
  return nameWords(name)
    .flatMap((w) => w.split(/(?<=\p{L})(?=\p{N})|(?<=\p{N})(?=\p{L})/u))
    .map((w) => w.replace(/i/g, 'l').replace(/rn/g, 'm').replace(/vv/g, 'w'));
}

/** True if `outer` holds every word of `inner`, in order and next to each other. */
function holds(outer: string[], inner: string[]): boolean {
  if (inner.length === 0 || inner.length > outer.length) return false;
  for (let i = 0; i + inner.length <= outer.length; i++) if (inner.every((w, j) => outer[i + j] === w)) return true;
  return false;
}

/**
 * True if one name could pass for the other, or for the same person with
 * something added: the same skeleton, one starting with the other ("Sam2",
 * "Sam (work)", "Ada - laptop"), or one holding the other's words ("Real
 * Sam").
 */
export function resembles(a: string, b: string): boolean {
  const sa = nameSkeleton(a);
  const sb = nameSkeleton(b);
  if (sa === '' || sb === '') return false;
  if (sa.startsWith(sb) || sb.startsWith(sa)) return true;
  const ta = nameTokens(a);
  const tb = nameTokens(b);
  return holds(ta, tb) || holds(tb, ta);
}

const LATIN = /\p{Script=Latin}/u;
// Scripts with letters that look like Latin ones. A name in one of them can
// spell another name, or "You", without a single Latin letter ("MAX" in
// Greek capitals), so such names always show the start of their code, and
// so do Latin names in a room where one appears.
const LOOKALIKE_SCRIPTS = ['Cyrillic', 'Greek', 'Armenian', 'Cherokee', 'Lisu', 'Coptic', 'Canadian_Aboriginal', 'Tifinagh', 'Vai', 'Osage', 'Deseret', 'Georgian', 'Old_Italic', 'Runic']
  .map((name) => new RegExp(`\\p{Script=${name}}`, 'u'));
const lookalikeScript = (name: string) => LOOKALIKE_SCRIPTS.some((s) => s.test(name));

/** Who we are in this room. */
export interface Identity {
  slot: number;
  signPublic: Uint8Array;
  /** Our receiving keys still kept, by number (the current one and, briefly, the one before). */
  boxes: Map<number, BoxKey>;
  /** True if this tab posted the record with this signature hash (signatureHash). */
  posted?: (hash: string) => boolean;
  /** The roster key, if we have it (the creator always does; others once admitted). */
  roster?: Uint8Array | null;
  /** The creator's name key secret, to read the names joiners seal to it. */
  nameSecret?: Uint8Array | null;
  /**
   * For the creator: whether a join carries a valid proof that its sender
   * had the invite link for its place, or null when this tab holds no
   * invite for the place.
   */
  checkProof?: ((slot: number, join: { key: string; box: string; proof: string | null }) => boolean | null) | undefined;
  /** For a joiner: inviteCheck of the secret in the link they used. */
  inviteCheck?: string | null | undefined;
}

/** What one record changed, for the page to show. */
export type RoomEvent =
  | { kind: 'message'; message: Message }
  | { kind: 'updated'; message: Message }
  | { kind: 'joined'; member: Member }
  | { kind: 'waiting'; member: Member }
  | { kind: 'removed'; member: Member | null; slot: number }
  | { kind: 'renamed'; name: string }
  | { kind: 'invited'; slot: number; label: string }
  | { kind: 'keys'; slot: number; n: number }
  | { kind: 'box'; slot: number };

export class RoomState {
  readonly members = new Map<number, Member>();
  readonly labels = new Map<number, string>();
  readonly removed = new Set<number>();
  readonly messages: Message[] = [];
  private readonly byId = new Map<string, Message>();
  /** Our copies of other members' sending chains. */
  readonly chains = new Map<number, Chain>();
  name = '';
  /** Records that failed to decrypt or verify (never shown). */
  rejected = 0;
  /** Messages we hold no key for: sent before we joined, or before their key reached us. */
  unreadable = 0;
  /** Key deliveries to us sealed to a receiving key we no longer have. */
  lostDeliveries = 0;
  /** The highest receiving key number of ours that opened a key delivery. */
  deliveredMax = -1;
  /** Something contradicts what this tab already knew: the history was tampered with. */
  conflict = false;
  /** Records from our place, made with our keys, that this tab did not post: another copy of our keys is in use. */
  cloned = false;
  /**
   * Senders whose key delivery to us was sealed to a receiving key we had
   * replaced well before. The delivery is signed by its sender (and its
   * time is theirs), so it names them: they were shown an old key of ours,
   * or chose to use one.
   */
  readonly staleFrom = new Set<number>();
  /** When the creator says the room ends (signed with the room's name), or null. */
  ends: number | null = null;
  /**
   * Members who showed different members different things: "keys" (signed
   * evidence: a key delivery that contradicts a chain we hold, or that
   * skips far ahead of it), "order" (their signed records went backwards in
   * the history: they, or the server reordering them, are splitting the
   * room).
   */
  readonly forks = new Map<number, 'keys' | 'order'>();
  /**
   * Senders whose chain went to others after we were let in, at a
   * generation we do not have: since when (Date.now()), that generation,
   * and how many records since showed it again (another delivery that
   * skipped us, or a message on that chain). Cleared once it reaches us.
   * The page warns only when it lasts and was seen more than once: an
   * honest sender whose view was stale catches up at their next check.
   */
  private readonly skippedSince = new Map<number, { since: number; gen: number; seen: number }>();
  /** Each sender's next allowed place: records only move forward in an honest sender's history. */
  private readonly nextPlace = new Map<number, { gen: number; index: number }>();
  /** Outer signatures of messages already placed, so a replay is not taken for a step back. */
  private readonly placed = new Set<string>();
  /** How many records we have applied, and when our own admission came (for the creator, at once). */
  private applied = 0;
  private admittedAt: number | null = null;
  /** The clock, for tests. */
  now: () => number = () => Date.now();
  /**
   * Receipts that contradict what we read: "claimer:about" means the
   * claimer's receipts say they read something else from `about` at a
   * place where we read a message. Receipts are the claimer's word: either
   * they are false, or the sender (maybe with the server) is showing
   * members different conversations.
   */
  readonly forkNotes = new Set<string>();
  /** The commitment seen first for each sender's place ("slot:gen:index"). */
  private readonly commits = new Map<string, string>();
  /**
   * For the creator: places where a second join with a valid proof came
   * after one was let in. Two people had the link; nobody can tell who is
   * who, so the place is closed.
   */
  readonly contested = new Set<number>();
  /** For the creator: places with a join whose proof did not check out (a damaged or forged invite). */
  readonly badProof = new Set<number>();
  /** For a joiner: the creator's invite for our place says our link's secret is not the one it made. */
  inviteMismatch = false;
  /** The roster key, which decrypts names, labels and the room's name; null until we are admitted. */
  private rk: Uint8Array | null;
  /** The creator's name key, from its join: joiners seal their names to it. */
  creatorNameKey: Uint8Array | null = null;
  /** Encrypted names, labels and room name waiting for the roster key. */
  private readonly memberNameRaw = new Map<number, string>();
  private readonly labelRaw = new Map<number, string>();
  private roomNameRaw: string | null = null;
  /** Goes up whenever names, labels or the room's name were decrypted: the page redraws them. */
  rosterVersion = 0;
  /** What we read from each sender, by place ("gen:index" to content hash). */
  private readonly readAt = new Map<number, Map<string, string>>();
  /** The newest place we read from each sender, and what we last put in a receipt. */
  private readonly latest = new Map<number, Ack>();
  /** Receipts about places we have not read (yet), newest per claimer and sender. */
  private readonly pending = new Map<string, Ack & { claimer: number }>();
  /** When we announced each of our receiving keys (our own clock). */
  private readonly ownBoxTimes = new Map<number, number>();
  private readonly boxPins = new Map<number, { n: number; key: Uint8Array }>();
  /** Records seen, by sender and id. */
  private readonly seen = new Set<string>();
  private named = false;
  /** Joins waiting for the creator's admit, by slot. */
  private readonly waiting = new Map<number, Member[]>();
  /** The signing key admitted (or pinned) for each slot. */
  private readonly admitted = new Map<number, Uint8Array>();
  private readonly pinned = new Set<number>();
  /** Slots whose admit record we have seen. */
  readonly admitSeen = new Set<number>();
  /** Slots whose signed removal we have seen in the history. */
  readonly removalSeen = new Set<number>();
  /** When the creator says it created the room (from its join). */
  createdAt: number | null = null;
  private readonly sodium: Sodium;
  private readonly key: Uint8Array;
  private readonly roomId: string;
  private readonly me: Identity;

  constructor(sodium: Sodium, controlKey: Uint8Array, roomId: string, me: Identity, chains: Map<number, Chain> = new Map(), pins: Pins = {}) {
    this.sodium = sodium;
    this.key = controlKey;
    this.roomId = roomId;
    this.me = me;
    this.rk = me.roster ?? null;
    for (const [slot, c] of chains) this.chains.set(slot, c);
    for (const [slot, k] of pins.known ?? []) {
      this.admitted.set(slot, k);
      this.pinned.add(slot);
    }
    for (const slot of pins.removed ?? []) this.removed.add(slot);
    for (const [slot, b] of pins.boxes ?? []) this.boxPins.set(slot, b);
  }

  /** The roster key, once we have it, for the page to keep. */
  rosterKey(): Uint8Array | null {
    return this.rk;
  }

  /** Decrypts every name, label and room name waiting for the roster key. */
  private resolve(): void {
    const rk = this.rk;
    if (!rk) return;
    let changed = false;
    for (const [slot, raw] of this.memberNameRaw) {
      const m = this.members.get(slot);
      if (!m) continue; // their join may come later
      this.memberNameRaw.delete(slot);
      const n = openBoxedName(this.sodium, rk, raw, this.roomId, 'member', slot);
      if (validName(n, MAX_NAME_LENGTH, false)) {
        m.name = n;
        changed = true;
      } else {
        this.rejected++;
      }
    }
    for (const [slot, raw] of this.labelRaw) {
      this.labelRaw.delete(slot);
      const n = openBoxedName(this.sodium, rk, raw, this.roomId, 'label', slot);
      if (validName(n, MAX_NAME_LENGTH, true)) {
        this.labels.set(slot, n);
        changed = true;
      } else {
        this.rejected++;
      }
    }
    if (this.roomNameRaw !== null) {
      const n = openBoxedName(this.sodium, rk, this.roomNameRaw, this.roomId, 'room', 0);
      this.roomNameRaw = null;
      if (validName(n, MAX_ROOM_NAME_LENGTH, true, true)) {
        this.name = n;
        changed = true;
      } else {
        this.rejected++;
      }
    }
    if (changed) this.rosterVersion++;
  }

  /** Gives a new member the newest receiving key this tab knew for their place. */
  private pinBox(m: Member): void {
    const pin = this.boxPins.get(m.slot);
    if (pin && pin.n > m.boxN) {
      m.boxKey = pin.key;
      m.boxN = pin.n;
    }
  }

  private same(a: Uint8Array, b: Uint8Array): boolean {
    return a.length === b.length && this.sodium.memcmp(a, b);
  }

  /** Applies one stored record, as the server says `from` posted it. */
  apply(from: number, bytes: Uint8Array): RoomEvent | null {
    this.applied++;
    if (bytes[0] === MESSAGE_VERSION) return this.incoming(from, bytes);
    if (bytes[0] !== CONTROL_VERSION) {
      this.rejected++;
      return null;
    }
    const opened = openControl(this.sodium, this.key, this.roomId, from, bytes);
    if (!opened) {
      this.rejected++;
      return null;
    }
    const r = opened.record;
    // Joins also count by key: a forged join reusing a real one's id must
    // not hide it.
    const seenKey = r.t === 'join' ? `${from}:${r.id}:${r.key}` : `${from}:${r.id}`;
    if (this.seen.has(seenKey)) return null;
    if (r.t === 'join') {
      const signKey = decodeKey(this.sodium, r.key);
      const boxKey = decodeKey(this.sodium, r.box);
      // Only the creator's join carries a name key (and its name boxed).
      const nameKey = r.namekey !== undefined ? decodeKey(this.sodium, r.namekey) : null;
      const join = { key: r.key, box: r.box, proof: r.proof ?? null };
      // A second person with the link for a place already taken: only the
      // creator can check its proof, and then closes the place.
      if (from !== 0 && this.members.has(from) && signKey && this.me.checkProof && !this.same(this.members.get(from)!.signKey, signKey) &&
        verifySignature(this.sodium, opened, signKey) && this.me.checkProof(from, join) === true) {
        this.contested.add(from);
      }
      if (this.members.has(from) || this.removed.has(from) || !signKey || !boxKey || !boxKeyOk(this.sodium, boxKey) ||
        (from === 0) !== (nameKey !== null) || (nameKey !== null && !boxKeyOk(this.sodium, nameKey)) || !verifySignature(this.sodium, opened, signKey)) {
        this.rejected++;
        return null;
      }
      // A joiner's name is sealed to the creator, who alone reads it here;
      // everyone else learns it from the creator's admit.
      let name = '';
      if (from !== 0 && this.me.nameSecret && this.creatorNameKey) {
        const n = openSealedName(this.sodium, r.name, this.creatorNameKey, this.me.nameSecret, { roomId: this.roomId, slot: from, key: r.key, box: r.box });
        if (validName(n, MAX_NAME_LENGTH, false)) name = n;
      }
      const member: Member = {
        slot: from, name, signKey, boxKey, boxN: 0, code: safetyCode(this.sodium, signKey), removed: false,
        join,
        joinedAt: r.time,
      };
      const expected = this.admitted.get(from);
      if (expected || from === 0) {
        // The creator (whose key the invite link pins), or an admitted member.
        if (expected && !this.same(expected, signKey)) {
          // Another key for the creator's place, which only the creator's
          // token can post to, means the server forged it. For other places
          // it may be a stray join that was never admitted: refuse it only.
          if (from === 0 && this.pinned.has(0)) this.conflict = true;
          this.rejected++;
          return null;
        }
        this.seen.add(seenKey);
        this.pinBox(member);
        this.members.set(from, member);
        this.waiting.delete(from);
        if (from === 0 && this.me.slot === 0) this.admittedAt ??= this.applied;
        if (from === 0) {
          this.createdAt = r.time;
          this.creatorNameKey = nameKey;
          this.memberNameRaw.set(0, r.name);
        }
        this.resolve();
        return { kind: 'joined', member };
      }
      // Anyone else waits for the creator's admit. The creator keeps only
      // joins whose proof checks out, all of them (so junk cannot crowd out
      // the real one); others keep a bounded list they never act on.
      const proof = this.me.checkProof ? this.me.checkProof(from, join) : null;
      if (proof === false) {
        this.badProof.add(from);
        this.rejected++;
        return null;
      }
      const list = this.waiting.get(from) ?? [];
      if ((proof !== true && list.length >= MAX_WAITING) || list.some((m) => this.same(m.signKey, signKey))) return null;
      this.seen.add(seenKey);
      list.push(member);
      this.waiting.set(from, list);
      return { kind: 'waiting', member };
    }
    const sender = this.members.get(from);
    if (!sender || sender.removed || !verifySignature(this.sodium, opened, sender.signKey) ||
      ((r.t === 'room' || r.t === 'invite' || r.t === 'remove' || r.t === 'admit') && from !== 0)) {
      this.rejected++;
      return null;
    }
    this.seen.add(seenKey);
    // Signed with our own key, so only a copy of our keys can have made it
    // (the server cannot): a record of ours this tab never posted is a copy's.
    if (from === this.me.slot && this.me.posted && !this.me.posted(signatureHash(this.sodium, opened.signature))) this.cloned = true;
    switch (r.t) {
      case 'room':
        if (this.named) return null;
        this.named = true;
        this.ends = r.ends;
        this.roomNameRaw = r.name;
        this.resolve();
        return this.name ? { kind: 'renamed', name: this.name } : null;
      case 'invite':
        if (this.labels.has(r.slot)) return null;
        if (r.slot === this.me.slot && this.me.inviteCheck && r.check !== this.me.inviteCheck) this.inviteMismatch = true;
        this.labels.set(r.slot, ''); // the label itself once we have the roster key
        this.labelRaw.set(r.slot, r.label);
        this.resolve();
        return { kind: 'invited', slot: r.slot, label: this.labels.get(r.slot) ?? '' };
      case 'admit': {
        const k = decodeKey(this.sodium, r.key);
        if (!k) {
          this.rejected++;
          return null;
        }
        const first = !this.admitSeen.has(r.slot);
        this.admitSeen.add(r.slot);
        if (r.slot === this.me.slot) this.admittedAt ??= this.applied;
        const prior = this.admitted.get(r.slot);
        if (prior) {
          // An honest creator admits one key per place, ever: a second one
          // means someone is showing members different rooms.
          if (!this.same(prior, k)) {
            this.conflict = true;
            return null;
          }
          // A place we knew already (after a reload): its name is here.
          if (first && !this.removed.has(r.slot)) {
            this.memberNameRaw.set(r.slot, r.name);
            this.openOwnRoster(r.slot, r.roster);
            this.resolve();
          }
          return null;
        }
        if (this.removed.has(r.slot)) return null;
        this.admitted.set(r.slot, k);
        this.memberNameRaw.set(r.slot, r.name);
        this.openOwnRoster(r.slot, r.roster);
        this.resolve();
        const m = (this.waiting.get(r.slot) ?? []).find((c) => this.same(c.signKey, k));
        this.waiting.delete(r.slot);
        if (!m) return null; // their join may come later
        this.pinBox(m);
        this.members.set(r.slot, m);
        this.resolve();
        return { kind: 'joined', member: m };
      }
      case 'remove': {
        this.removalSeen.add(r.slot);
        this.removed.add(r.slot);
        this.waiting.delete(r.slot);
        const member = this.members.get(r.slot) ?? null;
        if (member) member.removed = true;
        this.forget(r.slot);
        return { kind: 'removed', member, slot: r.slot };
      }
      case 'box': {
        const boxKey = decodeKey(this.sodium, r.box);
        if (!boxKey || !boxKeyOk(this.sodium, boxKey)) {
          this.rejected++;
          return null;
        }
        if (from === this.me.slot) this.ownBoxTimes.set(r.n, r.time);
        // One number, one key. Both records are signed by the member, so
        // only they (or a copy of their keys) made two: signed evidence
        // against them, not against the room's history. Keep the first.
        if (r.n === sender.boxN && !this.same(boxKey, sender.boxKey)) {
          if (from !== this.me.slot) this.forks.set(from, 'keys');
          return null;
        }
        if (r.n <= sender.boxN) return null; // numbers only go up
        // One at a time: a member's tab never skips ahead. A big jump is
        // someone with a copy of their keys, or a server hiding many
        // records; either way the number is not taken, so it cannot shut
        // out the member's own later keys.
        if (r.n > sender.boxN + MAX_BOX_STEP) {
          if (from !== this.me.slot) this.forks.set(from, this.forks.get(from) ?? 'order');
          return null;
        }
        sender.boxKey = boxKey;
        sender.boxN = r.n;
        return { kind: 'box', slot: from };
      }
      case 'keys': {
        if (from === this.me.slot) return null;
        const place = { roomId: this.roomId, slot: from, gen: r.gen, index: r.index };
        // An honest sender's deliveries and messages only move forward.
        this.notePlace(from, r.gen, r.index, false);
        // One place, one chain: every delivery for it commits to the same
        // key, whoever it went to. Two commitments for one place show a
        // sender handing different groups different chains, even to members
        // who hold neither.
        const placeKey = `${from}:${r.gen}:${r.index}`;
        const committed = this.commits.get(placeKey);
        if (committed !== undefined && committed !== r.commit) this.forks.set(from, 'keys');
        else if (committed === undefined) this.commits.set(placeKey, r.commit);
        // A chain we hold, at or before this place, must step to the key
        // this delivery commits to: one chain per place, for everyone. One
        // far ahead of it is no honest step either.
        const held = this.chains.get(from);
        if (held && held.gen === r.gen && held.index <= r.index) {
          if (r.index - held.index > MAX_SKIP) {
            this.forks.set(from, 'keys');
          } else {
            const trial = { gen: held.gen, index: held.index, ck: held.ck.slice() };
            advanceChain(this.sodium, trial, r.index);
            if (chainCommit(this.sodium, trial.ck, place) !== r.commit) this.forks.set(from, 'keys');
            this.sodium.memzero(trial.ck);
          }
        }
        const entry = r.to.find((e) => e.slot === this.me.slot);
        // Keys that went to others after we were let in, at a generation we
        // do not have: we may be being left out. So may we be when our
        // entry is there but will not open (sealed to a key we never had or
        // no longer hold, or not to us at all): it is the same to us.
        const have = held !== undefined && held.gen >= r.gen;
        const leftOut = () => {
          if (have || this.admittedAt === null || !this.members.has(this.me.slot) || this.removed.has(this.me.slot)) return;
          const s = this.skippedSince.get(from);
          if (!s || r.gen > s.gen) this.skippedSince.set(from, { since: s?.since ?? this.now(), gen: r.gen, seen: (s?.seen ?? 0) + 1 });
          else s.seen++;
        };
        if (!entry) {
          leftOut();
          return null;
        }
        // Sealed to a key we had replaced well before it was sent: the sender
        // was shown an old key of ours (the server left out our newer one),
        // or used one on purpose.
        for (const [n, t] of this.ownBoxTimes) if (n > entry.n && r.time > t + STALE_KEY_MS) this.staleFrom.add(from);
        const pair = this.me.boxes.get(entry.n);
        if (!pair) {
          this.lostDeliveries++;
          leftOut();
          return null;
        }
        const ck = openChainKey(this.sodium, entry.box, pair.publicKey, pair.secretKey, place, this.me.slot);
        if (!ck) {
          this.rejected++;
          leftOut();
          return null;
        }
        if (chainCommit(this.sodium, ck, place) !== r.commit) {
          // Our key is not the one everyone else was promised.
          this.sodium.memzero(ck);
          this.forks.set(from, 'keys');
          this.rejected++;
          leftOut();
          return null;
        }
        // Any delivery that opens marks its receiving key for replacement,
        // even one that does not move a chain.
        this.deliveredMax = Math.max(this.deliveredMax, entry.n);
        const current = this.chains.get(from);
        if (current && (r.gen < current.gen || (r.gen === current.gen && r.index <= current.index))) {
          this.sodium.memzero(ck); // never move a chain back
          return null;
        }
        this.forget(from);
        this.chains.set(from, { gen: r.gen, index: r.index, ck });
        this.skippedSince.delete(from);
        return { kind: 'keys', slot: from, n: entry.n };
      }
    }
  }

  private incoming(from: number, bytes: Uint8Array): RoomEvent | null {
    if (from === this.me.slot) {
      // Ours: shown when sent. One signed with our key that this tab never
      // posted was made by a copy of our keys (the server cannot sign).
      if (this.me.posted && checkOuterSignature(this.sodium, this.me.signPublic, this.roomId, from, bytes) && !this.me.posted(signatureHash(this.sodium, outerSignature(bytes)))) {
        this.cloned = true;
      }
      return null;
    }
    const sender = this.members.get(from);
    const at = messagePosition(bytes);
    // The place of every message signed by its sender counts, even one we
    // cannot read: records only move forward.
    if (sender && at && checkOuterSignature(this.sodium, sender.signKey, this.roomId, from, bytes)) {
      const sig = signatureHash(this.sodium, outerSignature(bytes));
      if (!this.placed.has(sig)) {
        this.placed.add(sig);
        this.notePlace(from, at.gen, at.index, true);
        // A message on a chain that skipped us shows it again.
        const s = this.skippedSince.get(from);
        if (s && at.gen >= s.gen) s.seen++;
      }
    }
    const chain = this.chains.get(from);
    if (!sender || sender.removed || !chain) {
      this.unreadable++;
      return null;
    }
    const record = openMessage(this.sodium, chain, this.roomId, from, bytes, sender.signKey);
    if (!record || !at) {
      this.unreadable++;
      return null;
    }
    return this.chat(from, record, at);
  }

  /**
   * Applies one of our own chat records. They come back from the server
   * unreadable to us (their keys are deleted when sending), so the page
   * applies them as it sends them.
   */
  applyOwn(record: MessageRecord, at?: { gen: number; index: number }): RoomEvent | null {
    return this.chat(this.me.slot, record, at);
  }

  /**
   * The receipts for our next message: the newest place read from every
   * place in the room, always all of them, so the message's size shows
   * nothing about what we read.
   */
  acks(): Ack[] {
    return Array.from({ length: MAX_SLOTS }, (_, slot) => this.latest.get(slot) ?? { slot, gen: 0, index: 0, h: NO_ACK });
  }

  /** Senders who have been leaving us out for at least `ms`, seen more than once. */
  skipped(ms: number): number[] {
    const t = this.now();
    return [...this.skippedSince].filter(([s, v]) => t - v.since >= ms && v.seen >= 2 && !this.removed.has(s)).map(([s]) => s);
  }

  /** Our admit carries the roster key, sealed to our join's key. */
  private openOwnRoster(slot: number, sealed: string): void {
    if (slot !== this.me.slot || this.rk) return;
    const first = this.me.boxes.get(0);
    const rk = first ? openRoster(this.sodium, sealed, first.publicKey, first.secretKey, this.roomId, slot) : null;
    if (rk) this.rk = rk;
    else this.rejected++;
  }

  /** Records a sender's signed place; one before where they already were is a step back. */
  private notePlace(slot: number, gen: number, index: number, message: boolean): void {
    const next = this.nextPlace.get(slot) ?? { gen: 0, index: 0 };
    if (gen < next.gen || (gen === next.gen && index < next.index)) {
      this.forks.set(slot, 'order');
      return;
    }
    this.nextPlace.set(slot, { gen, index: message ? index + 1 : index });
  }

  private noteRead(slot: number, at: { gen: number; index: number }, h: string): void {
    let m = this.readAt.get(slot);
    if (!m) {
      m = new Map();
      this.readAt.set(slot, m);
    }
    m.set(`${at.gen}:${at.index}`, h);
    if (m.size > 1000) m.delete(m.keys().next().value!);
    const cur = this.latest.get(slot);
    if (!cur || at.gen > cur.gen || (at.gen === cur.gen && at.index > cur.index)) this.latest.set(slot, { slot, gen: at.gen, index: at.index, h });
    for (const [k, c] of this.pending) {
      if (c.slot === slot && c.gen === at.gen && c.index === at.index) {
        if (c.h !== h) this.forkNotes.add(`${c.claimer}:${slot}`);
        this.pending.delete(k);
      }
    }
  }

  private checkClaim(claimer: number, a: Ack): void {
    if (a.gen === 0) return; // nothing read there
    const h = this.readAt.get(a.slot)?.get(`${a.gen}:${a.index}`);
    if (h !== undefined) {
      if (h !== a.h) this.forkNotes.add(`${claimer}:${a.slot}`);
      return;
    }
    this.pending.set(`${claimer}:${a.slot}`, { ...a, claimer });
  }

  /**
   * The rules for chat records: only the sender can edit or unsend a
   * message; anyone can react, once per reaction; nothing applies to a
   * message we do not have or that was unsent.
   */
  private chat(from: number, r: MessageRecord, at?: { gen: number; index: number }): RoomEvent | null {
    const key = `${from}:${r.id}`;
    if (this.seen.has(key)) return null;
    this.seen.add(key);
    // Receipts: what we read here, and what the sender says they read.
    if (at) this.noteRead(from, at, contentHash(this.sodium, r));
    if (r.t === 'msg') for (const a of r.seen) this.checkClaim(from, a);
    if (r.t === 'msg') {
      // A reply quotes what its target said when the reply arrived; one
      // whose target we never had says so for good.
      let quote: Message['quote'] = null;
      if (r.reply) {
        const target = this.byId.get(`${r.reply.author}:${r.reply.id}`) ?? null;
        quote = { author: r.reply.author, text: target && !target.deleted ? target.text : null, target: target && !target.deleted ? target : null };
      }
      const message: Message = { id: r.id, key, from, text: r.text, time: r.time, reply: r.reply, quote, edited: false, deleted: false, reactions: new Map() };
      this.messages.push(message);
      this.byId.set(key, message);
      return { kind: 'message', message };
    }
    // Edits and unsends name our own messages; reactions name their sender.
    const target = this.byId.get(r.t === 'react' ? `${r.author}:${r.target}` : `${from}:${r.target}`);
    if (!target || target.deleted) return null;
    switch (r.t) {
      case 'edit':
        if (target.from !== from || target.text === r.text) return null;
        target.text = r.text;
        target.edited = true;
        break;
      case 'unsend':
        if (target.from !== from) return null;
        target.deleted = true;
        target.text = '';
        target.reactions.clear();
        break;
      case 'react': {
        const who = target.reactions.get(r.emoji) ?? new Set<number>();
        if (r.on === who.has(from)) return null;
        if (r.on) who.add(from);
        else who.delete(from);
        if (who.size > 0) target.reactions.set(r.emoji, who);
        else target.reactions.delete(r.emoji);
        break;
      }
    }
    return { kind: 'updated', message: target };
  }

  /** A message we have, by its key (sender and id). */
  message(key: string): Message | undefined {
    return this.byId.get(key);
  }

  /** Deletes our copy of a sender's chain. */
  private forget(slot: number): void {
    const c = this.chains.get(slot);
    if (c) this.sodium.memzero(c.ck);
    this.chains.delete(slot);
  }

  /** Members who can currently receive keys: joined, not removed, not us. */
  recipients(): Member[] {
    return [...this.members.values()].filter((m) => !m.removed && m.slot !== this.me.slot);
  }

  /**
   * True if the join record for our slot is not ours: someone else (a
   * server working with someone who has the room key) announced keys for it.
   */
  impostor(): boolean {
    const k = this.admitted.get(this.me.slot) ?? this.members.get(this.me.slot)?.signKey;
    return k !== undefined && !this.same(k, this.me.signPublic);
  }

  /** True while our join waits for the creator's admit. */
  waitingForAdmit(): boolean {
    return !this.members.has(this.me.slot) && (this.waiting.get(this.me.slot)?.length ?? 0) > 0;
  }

  /**
   * For the creator: the joins waiting for an admit, in the order seen, for
   * each slot that was invited, not removed and not admitted.
   */
  joinsToAdmit(): Map<number, Member[]> {
    const out = new Map<number, Member[]>();
    for (const [slot, list] of this.waiting) {
      if (this.labels.has(slot) && !this.removed.has(slot) && !this.admitted.has(slot) && list.length > 0) out.set(slot, [...list]);
    }
    return out;
  }

  /**
   * The start of a member's safety code, shown with their name when it
   * could pass for another member's or for an invite made for someone else
   * (resembles: the same, or with something added),
   * for "You" (how the app shows your own messages), or uses a script with
   * Latin lookalikes (as do Latin names in a room with one). Three groups
   * (about 50 bits); all six if another member's code starts the same way.
   * Null when the name stands alone.
   */
  tagOf(slot: number): string | null {
    const m = this.members.get(slot);
    if (!m || m.name === '') return null;
    const twin = [...this.members.values()].some((o) => o.slot !== slot && o.name !== '' && resembles(o.name, m.name)) ||
      [...this.labels].some(([s, label]) => s !== slot && label !== '' && resembles(label, m.name));
    const posing = slot !== this.me.slot && nameWords(m.name).includes('you');
    const others = [...[...this.members.values()].filter((o) => o.slot !== slot).map((o) => o.name), ...[...this.labels].filter(([s]) => s !== slot).map(([, l]) => l)];
    const scripts = lookalikeScript(m.name) || (LATIN.test(m.name) && others.some(lookalikeScript));
    if (!twin && !posing && !scripts) return null;
    const short = m.code.slice(0, 17);
    const clash = [...this.members.values()].some((o) => o.slot !== slot && o.code.startsWith(short));
    return clash ? m.code : short;
  }

  /** The name to show for a slot: their own (with its tag), else the invite's label. */
  nameOf(slot: number): string {
    const m = this.members.get(slot);
    // Names stay unknown until we have the roster key.
    if (!m || m.name === '') return this.labels.get(slot) || (slot === 0 ? 'The creator' : `Member ${slot + 1}`);
    const tag = this.tagOf(slot);
    return tag ? `${m.name} (${tag})` : m.name;
  }

  /**
   * Whom the creator made a member's invite for, when their name does not
   * match it: someone may have used an invite meant for someone else.
   */
  invitedAs(slot: number): string | null {
    const m = this.members.get(slot);
    const label = this.labels.get(slot);
    if (!m || !label || m.name === '' || nameSkeleton(label) === nameSkeleton(m.name)) return null;
    return label;
  }

  /** For the creator: the join waiting at a place with this signing key, if any. */
  waitingJoin(slot: number, key: string): Member | undefined {
    return (this.waiting.get(slot) ?? []).find((m) => m.join.key === key);
  }

  /**
   * Marks a slot removed in this tab at once, before the room hears of it:
   * the creator stops sharing keys with it and never admits it.
   */
  removeLocally(slot: number): void {
    if (slot <= 0) return;
    this.removed.add(slot);
    this.waiting.delete(slot);
    const member = this.members.get(slot);
    if (member) member.removed = true;
    this.forget(slot);
  }

  /** Deletes every key this state holds, and what it decrypted. */
  wipe(): void {
    for (const slot of [...this.chains.keys()]) this.forget(slot);
    this.rk?.fill(0);
    this.rk = null;
    this.me.roster?.fill(0);
    this.me.nameSecret?.fill(0);
    this.creatorNameKey = null;
    for (const m of this.messages) {
      m.text = '';
      if (m.quote) m.quote.text = null;
    }
    this.messages.length = 0;
    this.byId.clear();
    this.readAt.clear();
    this.commits.clear();
    for (const m of this.members.values()) m.name = '';
    this.labels.clear();
    this.roomNameRaw = null;
  }
}
