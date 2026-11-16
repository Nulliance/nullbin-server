// Null Chats: the home page tab that creates one, the invite page that
// joins one, and the chat itself. The cryptography is in room-crypto.ts and
// the rules for trusting records in room-state.ts.
//
// Your access to a room lives in this browser tab (sessionStorage): the room
// key, your member token, your signing key, your current receiving keys,
// your current sending chain and the current chains of the others. Reloading
// keeps it; closing the tab ends it (unless the browser restores the tab).
// Message keys are deleted once used, and receiving keys soon after they are
// replaced, so after a reload only new messages can be read. Invites are
// single use, work for the chat's invite lifetime (5 to 60 minutes) and
// can be revoked; a chat may also need a password and has a member limit.
// The creator's tab lets each joiner in
// (THREAT_MODEL.md R25 says what a leaked link can and cannot do).
// The room opens in one tab at a time: a duplicated tab would send with the
// same keys.

import {
  ApiError,
  createInvite,
  createRoom,
  destroyRoom,
  fetchMembers,
  fetchRecords,
  joinRoom,
  postRecord,
  removeMember,
  type SlotState,
} from './api.ts';
import { cleanName } from './comments.ts';
import { announce, bindCopy, bindReveal, busy, copyText, el, formatCountdown, nextFrame, reveal, show, showProblem, showSection, swap } from './dom.ts';
import { generatePassword, MIN_PASSWORD_LENGTH } from './create.ts';
import { encodeInviteFragment, parseInviteFragment } from './link.ts';
import {
  MAX_BOX_N,
  MAX_COUNTER,
  MAX_MESSAGE_LENGTH,
  ROOM_KEY_BYTES,
  controlKey,
  encodeKey,
  newChain,
  newRecordId,
  sealChainKey,
  sealControl,
  cleanText,
  nameAllowed,
  signatureHash,
  outerSignature,
  MESSAGE_VERSION,
  chainCommit,
  boxName,
  sealName,
  sealRoster,
  decodeKey,
  safetyCode,
  openControl,
  sealMessage,
  verifySignature,
  joinProof,
  inviteCheck,
  checkJoinProof,
  roomPasswordKey,
  INVITE_TTLS,
  MAX_SLOTS,
  MIN_MEMBERS,
  REACTIONS,
  type Chain,
  type ControlRecord,
  type MessageRecord,
} from './room-crypto.ts';
import { RoomState, type BoxKey, type Member, type Message, type RoomEvent } from './room-state.ts';
import { loadSodium, type Sodium } from './sodium.ts';

/** Messages sent with one chain before it is replaced by a fresh one. */
const ROTATE_AFTER = 50;
/** A receiving key that has had a key delivery is replaced this soon after, at the earliest. */
const BOX_ROTATE_MS = 3 * 60_000; // at most this often: each change is a record, and a room holds 1,000
/** A replaced receiving key is kept this long, for deliveries already on their way, then deleted. */
const BOX_GRACE_MS = 120_000;

interface StoredBox {
  n: number;
  secret: string;
  retired: number | null; // when it was replaced (Date.now())
}

interface StoredChain {
  gen: number;
  index: number;
  ck: string;
}

/** What this tab holds for one room. */
interface Session {
  key: string; // room key, base64url
  slot: number;
  member: string; // member token
  name: string; // our name, to announce us again if our join was lost
  sign: string; // Ed25519 secret key
  boxes: StoredBox[]; // our receiving keys still kept: the current (highest n) and recently replaced ones
  boxRotate: boolean; // the current receiving key has had a delivery: replace it
  boxRotated: number; // when it was last replaced (Date.now())
  pendingBox: { n: number; secret: string } | null; // a new receiving key being announced
  owner: string | null; // owner token, for the creator only
  chain: StoredChain | null; // our sending chain
  sentTo: number[]; // slots holding our current chain
  sent: number; // messages sent with the current chain
  rotate: boolean; // replace our chain before the next message
  peers: (StoredChain & { slot: number })[];
  known: { slot: number; key: string }[]; // signing keys we trust by slot: the creator's (from the invite) and admitted members'
  invites: { slot: number; secret: string; exp: number }[]; // the creator's invite secrets, to check joins' proofs, and when each stops working (ms)
  password: string | null; // the creator's: the chat's password key (never the password), to check joins' proofs
  settings: { max: number; ttl: number } | null; // the creator's own choices, kept here: never taken back from the server
  joinProof: string | null; // our join's proof, to post the same join again if it was lost
  inviteCheck: string | null; // for a joiner: what the creator's invite record should say about our link's secret
  roster: string | null; // the roster key (names, labels, the room's name): the creator's from the start, others' once admitted
  nameSecret: string | null; // the creator's name key secret: joiners seal their names to its public key
  removedSlots: number[]; // slots removed from the room
  posted: string[]; // hashes of the records this tab posted, saved before posting: any other made with our keys is a copy's
  peerBoxes: { slot: number; n: number; key: string }[]; // each member's newest receiving key seen: a history cannot roll it back
  verified: { slot: number; key: string }[]; // members whose safety code we compared, by signing key
}

const TOKEN = /^[A-Za-z0-9_-]{43}$/;
/** Hashes of posted records kept (a room holds 1,000 records; the rest allow for replies lost on the way). */
const MAX_POSTED = 2000;
const storageKey = (id: string) => `nullbin.room.${id}`;
const b64 = (sodium: Sodium, b: Uint8Array) => sodium.to_base64(b, sodium.base64_variants.URLSAFE_NO_PADDING);
const unb64 = (sodium: Sodium, s: string) => sodium.from_base64(s, sodium.base64_variants.URLSAFE_NO_PADDING);

function saveSession(id: string, s: Session): void {
  try {
    sessionStorage.setItem(storageKey(id), JSON.stringify(s));
  } catch {
    // Storage is off (some private modes): the room works until a reload.
  }
}

function clearSession(id: string): void {
  try {
    sessionStorage.removeItem(storageKey(id));
  } catch {
    // nothing stored
  }
}

function validChain(sodium: Sodium, c: unknown): c is StoredChain {
  if (typeof c !== 'object' || c === null) return false;
  const o = c as Record<string, unknown>;
  const n = (v: unknown, min: number) => typeof v === 'number' && Number.isInteger(v) && v >= min && v <= MAX_COUNTER;
  return n(o['gen'], 1) && n(o['index'], 0) && typeof o['ck'] === 'string' && bytesOf(sodium, o['ck'], 32);
}

function bytesOf(sodium: Sodium, s: unknown, length: number): boolean {
  if (typeof s !== 'string') return false;
  try {
    return unb64(sodium, s).length === length;
  } catch {
    return false;
  }
}

function loadSession(sodium: Sodium, id: string): Session | null {
  let v: unknown;
  try {
    v = JSON.parse(sessionStorage.getItem(storageKey(id)) ?? 'null');
  } catch {
    return null;
  }
  if (typeof v !== 'object' || v === null) return null;
  const o = v as Record<string, unknown>;
  const slotOk = (n: unknown) => typeof n === 'number' && Number.isInteger(n) && n >= 0 && n < 20;
  const pending = o['pendingBox'] as Record<string, unknown> | null | undefined;
  const ok = typeof o['key'] === 'string' && TOKEN.test(o['key']) && slotOk(o['slot']) &&
    typeof o['name'] === 'string' && o['name'] !== '' && o['name'] === cleanName(o['name']) &&
    (pending === null || (typeof pending === 'object' && pending !== undefined && typeof pending['n'] === 'number' &&
      Number.isInteger(pending['n']) && pending['n'] >= 1 && pending['n'] <= MAX_COUNTER && bytesOf(sodium, pending['secret'], 32))) &&
    typeof o['member'] === 'string' && TOKEN.test(o['member']) &&
    bytesOf(sodium, o['sign'], sodium.crypto_sign_SECRETKEYBYTES) &&
    Array.isArray(o['boxes']) && o['boxes'].length >= 1 && o['boxes'].length <= 8 && o['boxes'].every((b: unknown) => {
      const x = (typeof b === 'object' && b !== null ? b : {}) as Record<string, unknown>;
      return typeof x['n'] === 'number' && Number.isInteger(x['n']) && x['n'] >= 0 && x['n'] <= MAX_COUNTER && bytesOf(sodium, x['secret'], 32) &&
        (x['retired'] === null || (typeof x['retired'] === 'number' && Number.isFinite(x['retired'])));
    }) &&
    typeof o['boxRotate'] === 'boolean' && typeof o['boxRotated'] === 'number' && Number.isFinite(o['boxRotated']) &&
    (o['owner'] === null || (typeof o['owner'] === 'string' && TOKEN.test(o['owner']))) &&
    (o['chain'] === null || validChain(sodium, o['chain'])) &&
    Array.isArray(o['sentTo']) && o['sentTo'].every(slotOk) &&
    typeof o['sent'] === 'number' && Number.isInteger(o['sent']) && o['sent'] >= 0 && typeof o['rotate'] === 'boolean' &&
    Array.isArray(o['peers']) && o['peers'].every((p: unknown) => validChain(sodium, p) && slotOk((p as unknown as Record<string, unknown>)['slot'])) &&
    Array.isArray(o['known']) && o['known'].length <= 20 && o['known'].every((k: unknown) => {
      const x = (typeof k === 'object' && k !== null ? k : {}) as Record<string, unknown>;
      return slotOk(x['slot']) && bytesOf(sodium, x['key'], 32);
    }) && (o['known'] as { slot: number }[]).some((k) => k.slot === 0) &&
    Array.isArray(o['removedSlots']) && o['removedSlots'].length <= 20 && o['removedSlots'].every(slotOk) &&
    Array.isArray(o['invites']) && o['invites'].length <= 20 && o['invites'].every((k: unknown) => {
      const x = (typeof k === 'object' && k !== null ? k : {}) as Record<string, unknown>;
      return slotOk(x['slot']) && bytesOf(sodium, x['secret'], 32) && typeof x['exp'] === 'number' && Number.isSafeInteger(x['exp']) && x['exp'] > 0;
    }) &&
    (o['password'] === null || (o['owner'] !== null && bytesOf(sodium, o['password'], 32))) &&
    // The creator always holds its settings; nobody else does.
    (o['owner'] === null ? o['settings'] === null : settingsOk(o['settings'])) &&
    (o['joinProof'] === null || bytesOf(sodium, o['joinProof'], 32)) &&
    (o['inviteCheck'] === null || bytesOf(sodium, o['inviteCheck'], 32)) &&
    (o['roster'] === null || bytesOf(sodium, o['roster'], 32)) &&
    (o['nameSecret'] === null || bytesOf(sodium, o['nameSecret'], 32)) &&
    // The creator holds both from the start.
    (o['owner'] === null || (o['roster'] !== null && o['nameSecret'] !== null)) &&
    Array.isArray(o['posted']) && o['posted'].length <= MAX_POSTED && o['posted'].every((w: unknown) => typeof w === 'string' && /^[A-Za-z0-9_-]{22}$/.test(w)) &&
    Array.isArray(o['verified']) && o['verified'].length <= 20 && o['verified'].every((k: unknown) => {
      const x = (typeof k === 'object' && k !== null ? k : {}) as Record<string, unknown>;
      return slotOk(x['slot']) && bytesOf(sodium, x['key'], 32);
    }) &&
    Array.isArray(o['peerBoxes']) && o['peerBoxes'].length <= 20 && o['peerBoxes'].every((k: unknown) => {
      const x = (typeof k === 'object' && k !== null ? k : {}) as Record<string, unknown>;
      return slotOk(x['slot']) && typeof x['n'] === 'number' && Number.isInteger(x['n']) && x['n'] >= 0 && x['n'] <= MAX_COUNTER && bytesOf(sodium, x['key'], 32);
    });
  return ok ? (o as unknown as Session) : null;
}

function settingsOk(v: unknown): boolean {
  if (typeof v !== 'object' || v === null) return false;
  const o = v as Record<string, unknown>;
  return Object.keys(o).sort().join(',') === 'max,ttl' && typeof o['max'] === 'number' && Number.isInteger(o['max']) &&
    o['max'] >= MIN_MEMBERS && o['max'] <= MAX_SLOTS && typeof o['ttl'] === 'number' && INVITE_TTLS.includes(o['ttl']);
}

/** A chat gives out each of its 19 places once: removed people and revoked or expired invites keep theirs. */
const NO_PLACES = 'This chat has given out all 19 places it ever can: removed people and revoked or expired invites keep theirs, so nobody new can join. Start a new chat to add people.';

function roomError(e: unknown, fallback: string): string {
  if (e instanceof ApiError) {
    if (e.status === 404) return 'Null Chats are turned off on this server, or the chat no longer exists.';
    if (e.status === 409 && e.message.includes('all its places')) return NO_PLACES;
    if (e.status === 409) return 'This chat is full: every place it allows is taken or invited. Revoke an invite, or remove someone, to make room.';
    if (e.status === 429 && e.message.includes('live burner rooms')) return 'Your network already has 10 Null Chats open. Delete one, or wait for one to expire.';
    if (e.status === 429) return 'Too many requests in a short time. Wait a minute, then try again.';
    if (e.status === 507) return 'This server can’t hold any more Null Chats right now. Try again later.';
  }
  return fallback;
}

/**
 * A new member's keys, and the join record that announces them. The
 * creator's join carries its name encrypted under the roster key, and the
 * name key joiners seal their names to; a joiner's carries its name sealed
 * to that key, so only the creator reads it before letting them in.
 */
function newIdentity(sodium: Sodium, name: string, names: { creator: { roster: Uint8Array; nameKey: Uint8Array; roomId: string } } | { sealTo: Uint8Array },
  invite?: { roomId: string; slot: number; secret: Uint8Array; password: Uint8Array | null }): { sign: Uint8Array; box: Uint8Array; join: ControlRecord & { t: 'join' } } {
  const sign = sodium.crypto_sign_keypair();
  const box = sodium.crypto_box_keypair();
  const key = encodeKey(sodium, sign.publicKey);
  const boxKey = encodeKey(sodium, box.publicKey);
  const join: ControlRecord & { t: 'join' } = 'creator' in names
    ? { t: 'join', id: newRecordId(sodium), time: Date.now(), name: boxName(sodium, names.creator.roster, name, names.creator.roomId, 'member', 0), key, box: boxKey, namekey: encodeKey(sodium, names.creator.nameKey) }
    : { t: 'join', id: newRecordId(sodium), time: Date.now(), name: sealName(sodium, name, names.sealTo, { roomId: invite!.roomId, slot: invite!.slot, key, box: boxKey }), key, box: boxKey };
  if (invite) join.proof = joinProof(sodium, invite.secret, invite.roomId, invite.slot, key, boxKey, invite.password);
  return { sign: sign.privateKey, box: box.privateKey, join };
}

function newSession(sodium: Sodium, roomKey: Uint8Array, slot: number, member: string, owner: string | null, name: string, sign: Uint8Array, box: Uint8Array, creator: Uint8Array): Session {
  return {
    key: b64(sodium, roomKey), slot, member, name, sign: b64(sodium, sign), boxes: [{ n: 0, secret: b64(sodium, box), retired: null }],
    boxRotate: false, boxRotated: Date.now(), pendingBox: null, owner, known: [{ slot: 0, key: b64(sodium, creator) }], removedSlots: [],
    invites: [], password: null, settings: null, joinProof: null, inviteCheck: null, chain: null, sentTo: [], sent: 0, rotate: false, peers: [], posted: [], peerBoxes: [], verified: [], roster: null, nameSecret: null,
  };
}

// --- The home page tab ---

/**
 * The home page's chat form. The page shows the paste form at "/" and this
 * one at "/chat"; the returned function switches between them in place
 * (the menu calls it), the old form fading out and the new one in.
 */
export function initRoomCreate(start: 'paste' | 'chat'): (service: 'paste' | 'chat') => void {
  const panels = { paste: el('create-form'), chat: el('room-create-form') };
  let selected: 'paste' | 'chat' = 'paste';
  let swaps = 0;
  const select = (service: 'paste' | 'chat') => {
    if (service === selected) return;
    const from = panels[selected];
    selected = service;
    // Switching back while the fade runs wins at once.
    swaps++;
    const mine = swaps;
    swap(from, panels[service], () => (mine === swaps ? mine : -1));
  };
  if (start === 'chat') {
    // Shown at once on load, with nothing fading.
    show(panels.paste, false);
    show(panels.chat);
    selected = 'chat';
  }

  const form = el<HTMLFormElement>('room-create-form');
  const you = el<HTMLInputElement>('room-you');
  const error = el('room-create-error');
  // The password: like a paste's, generated or typed, shown only on request.
  const pwSwitch = el<HTMLInputElement>('room-password-switch');
  const pwRow = el('room-password-row');
  const pw = el<HTMLInputElement>('room-password');
  const pwReveal = el<HTMLButtonElement>('room-password-reveal');
  const pwCopy = el<HTMLButtonElement>('room-password-copy');
  const clearPwError = () => {
    pw.classList.remove('is-invalid');
    pw.setAttribute('aria-invalid', 'false');
  };
  const syncPw = () => {
    show(pwRow, pwSwitch.checked);
    pw.required = pwSwitch.checked;
    pwCopy.disabled = pw.value === '';
    if (!pwSwitch.checked) clearPwError();
  };
  pwSwitch.addEventListener('change', () => {
    syncPw();
    if (pwSwitch.checked && pw.value === '') pw.focus();
  });
  pw.addEventListener('input', () => {
    clearPwError();
    pwCopy.disabled = pw.value === '';
  });
  bindReveal(pwReveal, pw);
  bindCopy(pwCopy, () => pw.value, 'Password copied', pw, 'The password is selected');
  el<HTMLButtonElement>('room-password-generate').addEventListener('click', () => {
    pw.value = generatePassword();
    pw.dispatchEvent(new Event('input'));
    if (pw.type !== 'text') pwReveal.click();
    announce('Generated a 20-character password. Copy it and send it separately from invites.');
  });
  syncPw();
  const maxInput = el<HTMLInputElement>('room-max');
  maxInput.addEventListener('input', () => {
    maxInput.classList.remove('is-invalid');
    maxInput.setAttribute('aria-invalid', 'false');
  });
  form.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    if (form.getAttribute('aria-busy') === 'true') return;
    show(error, false);
    const name = cleanName(you.value);
    if (name === '' || !nameAllowed(name)) {
      you.setAttribute('aria-invalid', 'true');
      error.textContent = name === '' ? 'Enter your name, so others know who you are.' : NAME_RULE;
      show(error);
      you.focus();
      return;
    }
    you.setAttribute('aria-invalid', 'false');
    const roomName = cleanName(el<HTMLInputElement>('room-name').value);
    if (!nameAllowed(roomName, true)) {
      error.textContent = 'Leave out stacks of accent marks in the chat’s name.';
      show(error);
      el('room-name').focus();
      return;
    }
    const password = pwSwitch.checked ? pw.value : '';
    if (pwSwitch.checked && password.length < MIN_PASSWORD_LENGTH) {
      pw.classList.add('is-invalid');
      pw.setAttribute('aria-invalid', 'true');
      pw.focus();
      return;
    }
    const expiresIn = Number(el<HTMLSelectElement>('room-expiry').value);
    const maxMembers = maxInput.value.trim() === '' ? NaN : Number(maxInput.value);
    // Each invite chooses how long it works when it is made; this is the
    // longest any of them may, signed with the chat's settings.
    const inviteTtl = 3600;
    if (!Number.isInteger(maxMembers) || maxMembers < MIN_MEMBERS || maxMembers > MAX_SLOTS) {
      maxInput.classList.add('is-invalid');
      maxInput.setAttribute('aria-invalid', 'true');
      maxInput.focus();
      return;
    }
    const done = busy(el<HTMLButtonElement>('room-create-submit'), 'Creating…');
    form.setAttribute('aria-busy', 'true');
    // Every secret made here is wiped at the end, whatever fails on the way.
    const secrets: Uint8Array[] = [];
    try {
      const sodium = await loadSodium();
      const created = await createRoom(expiresIn, maxMembers, inviteTtl);
      // The password never leaves this tab: only its Argon2id key is kept,
      // to check joins. (Argon2id blocks the page for a moment.)
      let pwKey: Uint8Array | null = null;
      if (password !== '') {
        await nextFrame();
        pwKey = roomPasswordKey(sodium, password, created.id);
        secrets.push(pwKey);
      }
      const roomKey = sodium.randombytes_buf(ROOM_KEY_BYTES);
      secrets.push(roomKey);
      // The roster key hides names, labels and the room's name from anyone
      // who has only the room key (any invite link).
      const roster = sodium.randombytes_buf(32);
      const nameKeys = sodium.crypto_box_keypair();
      secrets.push(roster, nameKeys.privateKey);
      const me = newIdentity(sodium, name, { creator: { roster, nameKey: nameKeys.publicKey, roomId: created.id } });
      secrets.push(me.sign, me.box);
      const session = newSession(sodium, roomKey, 0, created.memberToken, created.ownerToken, name, me.sign, me.box, me.sign.subarray(32));
      session.roster = b64(sodium, roster);
      session.nameSecret = b64(sodium, nameKeys.privateKey);
      session.password = pwKey ? b64(sodium, pwKey) : null;
      session.settings = { max: maxMembers, ttl: inviteTtl };
      if (pwKey) sodium.memzero(pwKey);
      const key = controlKey(sodium, roomKey);
      secrets.push(key);
      sodium.memzero(roomKey);
      // The room's name and when it ends, signed: members then check the
      // server's countdown against it.
      const named = sealControl(sodium, key, created.id, 0, me.sign,
        { t: 'room', id: newRecordId(sodium), time: Date.now(), name: boxName(sodium, roster, roomName, created.id, 'room', 0), ends: Date.now() + expiresIn * 1000,
          pw: password !== '', max: maxMembers, ttl: inviteTtl });
      sodium.memzero(roster);
      sodium.memzero(nameKeys.privateKey);
      // Both records are remembered as ours before they are posted: a record
      // signed with our key that this tab did not post is a copy's.
      const joinBytes = sealControl(sodium, key, created.id, 0, me.sign, me.join);
      session.posted.push(signatureHash(sodium, openControl(sodium, key, created.id, 0, joinBytes)!.signature));
      session.posted.push(signatureHash(sodium, openControl(sodium, key, created.id, 0, named)!.signature));
      try {
        // Join first: it carries the keys every reader checks against.
        await postRecord(created.id, created.memberToken, joinBytes as Uint8Array<ArrayBuffer>);
        await postRecord(created.id, created.memberToken, named as Uint8Array<ArrayBuffer>);
      } finally {
        sodium.memzero(key);
        sodium.memzero(me.sign);
        sodium.memzero(me.box);
      }
      saveSession(created.id, session);
      pw.value = '';
      window.location.assign(`/r/${created.id}`);
    } catch (e) {
      for (const s of secrets) s.fill(0);
      error.textContent = roomError(e, 'The Null Chat could not be created. Check your connection and try again.');
      show(error);
      error.focus();
    } finally {
      done();
      form.removeAttribute('aria-busy');
    }
  });
  return select;
}

// --- Opening a room: an invite, or this tab's session ---

export async function initRoom(id: string, fragment: string): Promise<void> {
  showSection('room');
  const sodium = await loadSodium();
  const existing = loadSession(sodium, id);
  if (fragment && !existing) {
    const invite = parseInviteFragment(sodium, fragment);
    if (!invite) {
      showProblem('This invite link is incomplete', 'The part after the # is missing or damaged. Ask the person who invited you to send the whole link again.');
      return;
    }
    joinFlow(sodium, id, invite.key, invite.invite, invite.creator, invite.secret, invite.slot, invite.password);
    return;
  }
  if (!existing) {
    showProblem('This Null Chat isn’t open in this tab', 'Your access to a Null Chat stays in the browser tab where you joined it. To get back in, ask someone in the chat for a new invite.');
    return;
  }
  openChat(sodium, id, existing);
}

function joinFlow(sodium: Sodium, id: string, roomKey: Uint8Array, inviteToken: string, creatorKey: Uint8Array, inviteSecret: Uint8Array, inviteSlot: number, passwordHint: boolean): void {
  const gate = el('room-join');
  reveal(gate);
  el('room-join-title').focus();
  const form = el<HTMLFormElement>('room-join-form');
  const nameInput = el<HTMLInputElement>('room-join-name');
  const error = el('room-join-error');
  // The chat's password, if it has one. The link only hints at it; the
  // creator's signed settings, read once the invite is used, decide.
  const pwField = el('room-join-password-field');
  const pwInput = el<HTMLInputElement>('room-join-password');
  bindReveal(el<HTMLButtonElement>('room-join-password-reveal'), pwInput);
  show(pwField, passwordHint);
  pwInput.addEventListener('input', () => pwInput.setAttribute('aria-invalid', 'false'));
  // The invite, once used: pressing Join again only repeats the check.
  let used: { memberToken: string; slot: number } | null = null;
  form.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    if (form.getAttribute('aria-busy') === 'true') return;
    show(error, false);
    const name = cleanName(nameInput.value);
    if (name === '' || !nameAllowed(name)) {
      nameInput.setAttribute('aria-invalid', 'true');
      error.textContent = name === '' ? 'Enter your name, so others know who you are.' : NAME_RULE;
      show(error);
      nameInput.focus();
      return;
    }
    nameInput.setAttribute('aria-invalid', 'false');
    const done = busy(el<HTMLButtonElement>('room-join-submit'), 'Joining…');
    form.setAttribute('aria-busy', 'true');
    let joined: { memberToken: string; slot: number };
    try {
      joined = used ?? await joinRoom(id, inviteToken);
      used = joined;
    } catch (e) {
      done();
      form.removeAttribute('aria-busy');
      if (e instanceof ApiError && e.status === 410 && e.message.includes('expired')) {
        showProblem('This invite has expired', 'Invites work for a short time after they’re made, from 5 minutes to an hour as the chat’s creator chose. Ask the person who invited you for a new one.');
      } else if (e instanceof ApiError && e.status === 410) {
        showProblem('This invite was already used or revoked', 'Each invite works once, and the person who made it can revoke it. Ask them for a new one.');
      } else if (e instanceof ApiError && e.status === 404) {
        showProblem('This Null Chat doesn’t exist', 'It may have expired or been deleted, or Null Chats are turned off on this server.');
      } else {
        error.textContent = roomError(e, 'Could not join. Check your connection and try again.');
        show(error);
      }
      return;
    }
    if (joined.slot !== inviteSlot) {
      // The server put us somewhere other than the place the invite was
      // made for: the creator's tab would never let us in there.
      done();
      form.removeAttribute('aria-busy');
      sodium.memzero(roomKey);
      showProblem('This invite was sent to the wrong place', 'The server put you in a different place in the chat from the one this invite was made for, so you can’t be let in. The server may have been tampered with. Tell the person who invited you.');
      return;
    }
    // The invite is used now. Check that its key really opens this room
    // (a chat app or someone in between may have changed the link) before
    // announcing ourselves: otherwise we would join as a member nobody can read.
    // Nothing is saved until the check passes: a tab never keeps a way in
    // with a key that may be wrong. If the room cannot be reached, say so
    // and let Join try the check again.
    const key0 = controlKey(sodium, roomKey);
    let opens: boolean | null = null;
    let gone = false;
    let nameKey: Uint8Array | null = null;
    // Whether the creator's signed settings ask for a password. Without
    // them (a server hiding them), a join without one is refused by the
    // creator, which fails safe.
    let needsPassword = false;
    try {
      for (let attempt = 0; opens === null && attempt < 3; attempt++) {
        if (attempt > 0) await new Promise((r) => setTimeout(r, 1500 * attempt));
        try {
          const first = await fetchRecords(id, joined.memberToken, 0);
          // The room key must open the creator's join, signed with the
          // creator's key from the link. It also carries the key our name
          // is sealed to.
          opens = first.records.some((r) => {
            if (r.from !== 0) return false;
            const o = openControl(sodium, key0, id, 0, r.data);
            if (o === null || o.record.t !== 'join' || o.record.key !== encodeKey(sodium, creatorKey) || !verifySignature(sodium, o, creatorKey) || o.record.namekey === undefined) return false;
            nameKey = decodeKey(sodium, o.record.namekey);
            return nameKey !== null;
          });
          // The first room record the creator signed holds its settings.
          for (const r of first.records) {
            if (r.from !== 0) continue;
            const o = openControl(sodium, key0, id, 0, r.data);
            if (o === null || o.record.t !== 'room' || !verifySignature(sodium, o, creatorKey)) continue;
            needsPassword = o.record.pw;
            break;
          }
        } catch (e) {
          if (e instanceof ApiError && e.status === 404) gone = true;
          if (gone) break;
        }
      }
    } finally {
      sodium.memzero(key0);
    }
    if (gone) {
      done();
      form.removeAttribute('aria-busy');
      sodium.memzero(roomKey);
      sodium.memzero(inviteSecret);
      showProblem('This Null Chat has ended', 'It self-destructed or expired just as you joined.');
      return;
    }
    if (opens === null) {
      done();
      form.removeAttribute('aria-busy');
      error.textContent = 'You’re in, but the chat could not be reached to check the invite. Press Join to try again, and keep this tab open: the invite is used up.';
      show(error);
      return;
    }
    if (!opens || !nameKey) {
      done();
      form.removeAttribute('aria-busy');
      sodium.memzero(roomKey);
      sodium.memzero(inviteSecret);
      showProblem('This invite link was damaged', 'The part after the # was changed on the way, so it cannot open the chat, and the invite is now used up. Ask the person who invited you for a new invite, and send it a different way if you can.');
      return;
    }
    // A chat with a password: ask for it now if it was not given. The
    // invite is used, so Join only repeats the check after this.
    if (needsPassword && pwInput.value === '') {
      done();
      form.removeAttribute('aria-busy');
      show(pwField);
      pwInput.setAttribute('aria-invalid', 'true');
      error.textContent = 'This chat has a password. Enter it to be let in: the person who invited you should have sent it separately from the link.';
      show(error);
      pwInput.focus();
      return;
    }
    // The password key goes into our join's proof; the creator's tab
    // checks it. A wrong one closes this invite (one try per invite).
    let pwKey: Uint8Array | null = null;
    if (needsPassword) {
      await nextFrame(); // Argon2id blocks the page for a moment
      try {
        pwKey = roomPasswordKey(sodium, pwInput.value, id);
      } catch {
        done();
        form.removeAttribute('aria-busy');
        pwInput.setAttribute('aria-invalid', 'true');
        error.textContent = 'That password is too long.';
        show(error);
        return;
      }
    }
    pwInput.value = '';
    // From here on, this tab's session is the way in.
    let me: ReturnType<typeof newIdentity>;
    let session: Session;
    let key: Uint8Array;
    let joinBytes: Uint8Array;
    try {
      me = newIdentity(sodium, name, { sealTo: nameKey }, { roomId: id, slot: joined.slot, secret: inviteSecret, password: pwKey });
      session = newSession(sodium, roomKey, joined.slot, joined.memberToken, null, name, me.sign, me.box, creatorKey);
      session.joinProof = me.join.proof ?? null;
      session.inviteCheck = inviteCheck(sodium, inviteSecret, id, joined.slot);
      key = controlKey(sodium, roomKey);
      // Our join is remembered as ours before it is posted (see post()).
      joinBytes = sealControl(sodium, key, id, joined.slot, me.sign, me.join);
      session.posted.push(signatureHash(sodium, openControl(sodium, key, id, joined.slot, joinBytes)!.signature));
      saveSession(id, session);
    } catch {
      done();
      form.removeAttribute('aria-busy');
      showProblem('This Null Chat can’t be opened', 'Something went wrong while joining. Ask the person who invited you for a new invite.');
      return;
    } finally {
      // Whatever happened, the link's keys (and the password's) leave memory here.
      sodium.memzero(inviteSecret);
      sodium.memzero(roomKey);
      if (pwKey) sodium.memzero(pwKey);
    }
    try {
      await postRecord(id, joined.memberToken, joinBytes as Uint8Array<ArrayBuffer>);
    } catch {
      // The chat sees that our join is missing and sends it again.
    } finally {
      sodium.memzero(key);
      sodium.memzero(me.sign);
      sodium.memzero(me.box);
      done();
      form.removeAttribute('aria-busy');
    }
    show(gate, false);
    openChat(sodium, id, session);
  });
}

// --- The chat ---

const VISIBLE_POLL_MS = 2500;
const HIDDEN_POLL_MS = 15000;
/** Messages from one person within this long form one run of bubbles. */
const GROUP_MS = 5 * 60_000;
/** A press this long on a touch screen opens a message's menu. */
const LONG_PRESS_MS = 450;
/** A view of the room older than this is fetched again before sending. */
const STALE_MS = 60_000;
/** A lost join announcement is sent again at most this often. */
const REJOIN_MS = 30_000;

/** A confirming click must come at least this long after the first. */
const CONFIRM_GAP_MS = 500;
/** How long keys may keep going to others but not to us before the page says so (a stale view catches up sooner). */
const SKIPPED_MS = 2 * 60_000;
/** How far the server's end time may pass the creator's signed one before the page says so (clocks differ). */
const ENDS_SLACK_MS = 10 * 60_000;
/** After waiting this long to be let in, the page explains what may be wrong. */
const WAIT_HINT_MS = 2 * 60_000;
/** How long past an invite's signed expiry the creator's tab still lets its join in (clocks differ; a background tab polls slowly). */
const INVITE_SLACK_MS = 10 * 60_000;

const NAME_RULE = 'Use a letter, digit or emoji, at most four digits (none in brackets), no check marks or stacks of accent marks, and no role such as admin or owner: names can’t look like the codes, marks or roles the app shows.';

/** Holding Enter or Space down must not click a button again and again. */
function noRepeat(b: HTMLElement): void {
  b.addEventListener('keydown', (e) => {
    if (e.repeat) e.preventDefault();
  });
}

/** Thrown when sending is refused because the room view is out of date. */
class NotSynced extends Error {}

function make<K extends keyof HTMLElementTagNameMap>(tag: K, cls: string, text?: string): HTMLElementTagNameMap[K] {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined) n.textContent = text; // never innerHTML
  return n;
}

function icon(name: string): SVGSVGElement {
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('class', 'nb-i');
  svg.setAttribute('aria-hidden', 'true');
  const use = document.createElementNS('http://www.w3.org/2000/svg', 'use');
  use.setAttribute('href', `#i-${name}`);
  svg.append(use);
  return svg;
}

const colour = (slot: number) => `nb-c${slot % 8}`;
const initial = (name: string) => (Array.from(name.trim())[0] ?? '?').toUpperCase();
const DIALOGS = ['room-invite-dialog', 'room-members-dialog', 'room-destroy-dialog'];

function openChat(sodium: Sodium, id: string, session: Session): void {
  document.body.classList.add('nb-in-room');
  /**
   * For the creator: whether a join proves it came from the invite link for
   * its place (and, in a chat with a password, that it knew the password),
   * or null when this tab made no invite for the place.
   */
  const proofOk = (slot: number, join: { key: string; box: string; proof: string | null }): boolean | null => {
    const invite = session.invites.find((i) => i.slot === slot);
    if (!invite) return null;
    if (join.proof === null) return false;
    const secret = unb64(sodium, invite.secret);
    const pwKey = session.password ? unb64(sodium, session.password) : null;
    try { return checkJoinProof(sodium, secret, id, slot, join.key, join.box, join.proof, pwKey); }
    finally {
      sodium.memzero(secret);
      if (pwKey) sodium.memzero(pwKey);
    }
  };
  reveal(el('room-chat'));
  const roomKey = unb64(sodium, session.key);
  const key = controlKey(sodium, roomKey);
  sodium.memzero(roomKey);
  const signSecret = unb64(sodium, session.sign);
  const signPublic = signSecret.slice(32); // an Ed25519 secret key ends with its public key
  const boxPair = (secret: string): BoxKey => {
    const secretKey = unb64(sodium, secret);
    return { secretKey, publicKey: sodium.crypto_scalarmult_base(secretKey) };
  };
  // Our receiving keys. A new one being announced is here too, so that
  // deliveries sealed to it open even if the announcement's reply was lost.
  const boxes = new Map<number, BoxKey>(session.boxes.map((b) => [b.n, boxPair(b.secret)]));
  if (session.pendingBox && !boxes.has(session.pendingBox.n)) boxes.set(session.pendingBox.n, boxPair(session.pendingBox.secret));
  const peers = new Map<number, Chain>(session.peers.map((p) => [p.slot, { gen: p.gen, index: p.index, ck: unb64(sodium, p.ck) }]));
  const posted = new Set(session.posted);
  // Hashes seen back in the history: those records are stored for good, and
  // their hashes are never trimmed.
  const confirmed = new Set<string>();
  const isPosted = (h: string) => {
    const ok = posted.has(h);
    if (ok) confirmed.add(h);
    return ok;
  };
  const state = new RoomState(sodium, key, id, {
    slot: session.slot, signPublic, boxes, posted: isPosted,
    roster: session.roster ? unb64(sodium, session.roster) : null,
    nameSecret: session.nameSecret ? unb64(sodium, session.nameSecret) : null,
    inviteCheck: session.inviteCheck,
    checkProof: session.slot !== 0 ? undefined : (slot, join) => proofOk(slot, join),
  }, peers, {
    known: new Map(session.known.map((k) => [k.slot, unb64(sodium, k.key)])),
    removed: session.removedSlots,
    boxes: new Map(session.peerBoxes.map((b) => [b.slot, { n: b.n, key: unb64(sodium, b.key) }])),
  });
  const currentBox = () => Math.max(...session.boxes.map((b) => b.n));
  let chain: Chain | null = session.chain ? { gen: session.chain.gen, index: session.chain.index, ck: unb64(sodium, session.chain.ck) } : null;
  const owner = session.owner;
  const log = el('room-messages');
  const title = el('room-title');
  const avatar = el('room-avatar');
  const status = el('room-status');
  const jump = el<HTMLButtonElement>('room-jump');
  const jumpCount = el('room-jump-count');
  const composer = el<HTMLFormElement>('room-composer');
  const text = el<HTMLTextAreaElement>('room-text');
  const send = el<HTMLButtonElement>('room-send');
  const context = el('room-context');
  const baseTitle = document.title; // the room's name stays out of the title, and so out of history
  const desktop = window.matchMedia('(hover: hover) and (pointer: fine)').matches;
  let after = 0;
  let deadline: number | null = null;
  let ended = false;
  let unread = 0;
  let timer = 0;
  let synced = 0; // when the last complete poll finished, Date.now()
  let rejoined = 0;
  /** Slots this tab has admitted and is waiting to see the admit for. */
  const admitting = new Set<number>();
  const admits = new Map<number, ControlRecord>();
  /** Invited places two different people proved they had the link for: nobody is let in through them. */
  const contested = new Set<number>();
  /** Places whose damaged-invite notice was shown. */
  const badProofShown = new Set<number>();
  /** Places whose over-the-limit notice was shown. */
  const overLimitShown = new Set<number>();
  /** Places closed because their invite expired before its join reached this tab, or the chat was full. */
  const lateShown = new Set<number>();
  /** Messages we could not read, counted after the first full fetch; more later may mean hidden key deliveries. */
  let unreadableBase: number | null = null;
  /** When we started waiting to be let in. */
  let waitingSince: number | null = null;
  let warnedNoRoom = false;
  let fetchedAt = 0;
  const warnedForks = new Set<string>();
  let warnedEnds = false;
  show(el('room-invite-open'), owner !== null);

  // Writes go one at a time, in order: a key delivery must reach the server
  // before the messages that need it. Each write checks first that the room
  // is still open: after it ends, the keys are wiped.
  let queue: Promise<unknown> = Promise.resolve();
  const exclusive = <T>(fn: () => Promise<T>): Promise<T | undefined> => {
    const guarded = () => (ended ? Promise.resolve(undefined) : fn());
    const run = queue.then(guarded, guarded);
    queue = run.catch(() => {});
    return run;
  };

  // Listeners on the window and document, removed when the room ends.
  const listening = new AbortController();

  // --- Ending: everything decrypted and every key leaves the page. ---
  const shutdown = () => {
    ended = true;
    releaseLock?.();
    listening.abort();
    sizes.disconnect();
    clearTimeout(timer);
    clearInterval(countdown);
    closeMenu(false);
    menu.remove();
    state.wipe();
    repliesTo.clear();
    shownAt.clear();
    if (chain) sodium.memzero(chain.ck);
    for (const k of [key, signSecret]) sodium.memzero(k);
    for (const b of boxes.values()) sodium.memzero(b.secretKey);
    boxes.clear();
    channel?.close();
    channel = null;
    for (const d of DIALOGS) el<HTMLDialogElement>(d).close();
    log.replaceChildren();
    nodes.clear();
    text.value = '';
    mode = null;
    show(context, false);
    for (const e of ['room-context-title', 'room-context-quote', 'room-member-list', 'room-member-count', 'room-invite-link', 'room-expires']) el(e).replaceChildren();
    title.textContent = 'Null Chat';
    avatar.textContent = 'B';
    document.title = baseTitle;
    document.body.classList.remove('nb-in-room');
    // Drop this tab's copy of the session's secrets from the page as well as
    // from storage (persist() writes nothing once ended). JavaScript cannot
    // erase strings, but nothing keeps them reachable any more.
    Object.assign(session, {
      key: '', member: '', sign: '', owner: null, password: null, settings: null, roster: null, nameSecret: null,
      boxes: [], pendingBox: null, chain: null, peers: [], invites: [], joinProof: null, inviteCheck: null,
      known: [], peerBoxes: [], posted: [], verified: [], sentTo: [], name: '',
    } satisfies Partial<Session>);
    // The chat's elements are replaced by clean copies: every listener on
    // them (and with it this chat's closures) goes too.
    for (const e of [log, composer, jump]) e.replaceWith(e.cloneNode(true));
  };
  const end = (heading: string, body: string) => {
    if (ended) return;
    shutdown();
    clearSession(id);
    showProblem(heading, body);
  };
  // The server stops answering once our place is closed. Someone never let
  // in most likely had their place closed by the creator (a wrong
  // password, an expired or revoked invite); the chat may also have ended.
  const gone = () => (session.slot !== 0 && !state.members.has(session.slot)
    ? end('You weren’t let in', state.passwordRequired
      ? 'The person who invited you closed your place without letting you in: the password may have been wrong, or the invite expired or was revoked. The chat may also have ended. Ask them for a new invite, and check the password with them.'
      : 'The person who invited you closed your place without letting you in, perhaps because the invite expired or was revoked, or the chat ended. Ask them for a new invite, sent another way.')
    : end('This Null Chat has ended', 'It self-destructed, expired, or the server restarted, or you were removed. Nothing in it can be read any more.'));

  // One tab at a time: a duplicated tab carries a copy of this session and
  // would send with the same keys. The first tab holds a lock on this place
  // in the room (released only when it closes, reloads or leaves the page,
  // never while the browser has frozen it); a tab that cannot get it is a
  // copy, and deletes its copy of the keys.
  let channel: BroadcastChannel | null = null;
  let releaseLock: (() => void) | null = null;
  const lockName = `nullbin-room-${id}-${session.slot}`;
  const refuse = () => {
    if (ended) return;
    shutdown();
    clearSession(id);
    showProblem('This Null Chat is open in another tab', 'A chat works in one tab at a time. Use the tab where you joined it. This tab’s copy of the chat’s keys has been deleted.');
  };
  const start = () => {
    if (!ended) timer = window.setTimeout(() => void poll(), 0);
  };

  const persist = () => {
    if (ended) return;
    session.chain = chain ? { gen: chain.gen, index: chain.index, ck: b64(sodium, chain.ck) } : null;
    session.peers = [...state.chains].map(([slot, c]) => ({ slot, gen: c.gen, index: c.index, ck: b64(sodium, c.ck) }));
    // Pin who is who and who was removed: a later history that says
    // otherwise is refused.
    const known = new Map(session.known.map((k) => [k.slot, k.key]));
    for (const m of state.members.values()) known.set(m.slot, encodeKey(sodium, m.signKey));
    session.known = [...known].map(([slot, k]) => ({ slot, key: k }));
    session.removedSlots = [...state.removed];
    session.peerBoxes = [...state.members.values()].map((m) => ({ slot: m.slot, n: m.boxN, key: b64(sodium, m.boxKey) }));
    const rk = state.rosterKey();
    if (rk) session.roster = b64(sodium, rk);
    saveSession(id, session);
  };

  /**
   * Posts one record. Its hash is saved first, so that when it comes back
   * it is known as ours; anything else made with our keys is a copy's. A
   * hash stays even if posting fails (a server could store a record and
   * still answer with an error); only the oldest of those not yet seen in
   * the history are dropped, past MAX_POSTED.
   */
  const post = async (bytes: Uint8Array) => {
    if (ended) throw new Error('ended');
    // A record is known by its signature, which re-encrypting it keeps.
    const sig = bytes[0] === MESSAGE_VERSION ? outerSignature(bytes) : openControl(sodium, key, id, session.slot, bytes)?.signature;
    if (!sig) throw new Error('unreadable record');
    const h = signatureHash(sodium, sig);
    if (!posted.has(h)) session.posted.push(h);
    posted.add(h);
    while (session.posted.length > MAX_POSTED) {
      const i = session.posted.findIndex((x) => !confirmed.has(x));
      if (i < 0) break;
      posted.delete(session.posted[i]!);
      session.posted.splice(i, 1);
    }
    persist();
    await postRecord(id, session.member, bytes as Uint8Array<ArrayBuffer>);
  };
  const control = (record: ControlRecord) => {
    if (ended) return Promise.reject(new Error('ended'));
    return post(sealControl(sodium, key, id, session.slot, signSecret, record));
  };

  /**
   * Makes sure every current member holds our current sending chain: a
   * fresh chain when we have none, after a removal and every ROTATE_AFTER
   * messages; otherwise our current position, to members who joined since.
   */
  const shareKeys = async () => {
    if (!chain || session.rotate || session.sent >= ROTATE_AFTER) {
      const gen = (chain?.gen ?? session.chain?.gen ?? 0) + 1;
      if (chain) sodium.memzero(chain.ck);
      chain = newChain(sodium, Math.min(gen, MAX_COUNTER));
      session.sentTo = [];
      session.sent = 0;
      session.rotate = false;
      persist();
    }
    const targets = state.recipients().filter((m) => !session.sentTo.includes(m.slot));
    const place = { roomId: id, slot: session.slot, gen: chain.gen, index: chain.index };
    const to: { slot: number; n: number; box: string }[] = [];
    for (const m of targets) {
      // One member's unusable key must not stop the others' deliveries.
      try {
        to.push({ slot: m.slot, n: m.boxN, box: sealChainKey(sodium, chain.ck, m.boxKey, place, m.slot) });
      } catch {
        // Their key is refused when read; nothing to send them.
      }
    }
    if (to.length === 0) return;
    await control({ t: 'keys', id: newRecordId(sodium), time: Date.now(), gen: chain.gen, index: chain.index, commit: chainCommit(sodium, chain.ck, place), to });
    session.sentTo.push(...to.map((e) => e.slot));
    persist();
  };

  /**
   * Replaces our receiving key soon after it had a key delivery, and
   * deletes replaced keys once deliveries on their way have had time to
   * arrive. A delivery recorded now cannot be opened with keys taken from
   * this tab later.
   */
  const dropRetired = () => {
    const now = Date.now();
    for (const b of session.boxes) {
      // (A key retired "in the future" means the clock went back: it goes too.)
      if (b.retired !== null && (now - b.retired >= BOX_GRACE_MS || b.retired > now)) {
        const pair = boxes.get(b.n);
        if (pair) sodium.memzero(pair.secretKey);
        boxes.delete(b.n);
      }
    }
    session.boxes = session.boxes.filter((b) => boxes.has(b.n));
    // At most 8 are kept (a session with more does not load): the oldest
    // replaced ones go first.
    while (session.boxes.length > 7 && session.boxes.some((b) => b.retired !== null)) {
      const oldest = session.boxes.filter((b) => b.retired !== null).reduce((x, y) => (y.n < x.n ? y : x));
      const pair = boxes.get(oldest.n);
      if (pair) sodium.memzero(pair.secretKey);
      boxes.delete(oldest.n);
      session.boxes = session.boxes.filter((b) => b !== oldest);
    }
  };
  let boxRecord: (ControlRecord & { t: 'box' }) | null = null;
  const rotateReceiving = async () => {
    const now = Date.now();
    dropRetired();
    if (session.boxRotate && now - session.boxRotated >= BOX_ROTATE_MS && currentBox() < MAX_BOX_N) {
      const n = currentBox() + 1;
      // The new key is stored before it is announced, and reused if the
      // announcement has to be sent again: if the server stored it but its
      // reply was lost, members may already be sealing to it.
      if (!session.pendingBox || session.pendingBox.n !== n) {
        const pair = sodium.crypto_box_keypair();
        session.pendingBox = { n, secret: b64(sodium, pair.privateKey) };
        boxes.set(n, { publicKey: pair.publicKey, secretKey: pair.privateKey });
        persist();
      }
      const pair = boxes.get(n)!;
      // Sent again unchanged, so a retry is the same record.
      if (boxRecord?.n !== n) boxRecord = { t: 'box', id: newRecordId(sodium), time: now, n, box: encodeKey(sodium, pair.publicKey) };
      await control(boxRecord);
      if (ended) return;
      for (const b of session.boxes) b.retired ??= now;
      session.boxes.push({ n, secret: session.pendingBox.secret, retired: null });
      session.pendingBox = null;
      // A delivery may already have opened with the new key (sealed to it
      // while its announcement's reply was lost): then it is replaced too.
      session.boxRotate = state.deliveredMax >= n;
      session.boxRotated = now;
    }
    persist();
  };

  /**
   * Announces us again if our join record never reached the server (the
   * page closed or the network failed right after joining). It carries the
   * same keys, from this tab's session.
   */
  /** The creator's public name key, from its secret (wiped right after). */
  const nameKeyOf = (secret: string) => {
    const s = unb64(sodium, secret);
    try { return encodeKey(sodium, sodium.crypto_scalarmult_base(s)); }
    finally { sodium.memzero(s); }
  };
  const rejoin = async () => {
    const first = boxes.get(0);
    if (!first || session.boxes.every((b) => b.n !== 0) || Date.now() - rejoined < REJOIN_MS) return;
    // A joiner's name is sealed to the creator's name key, from the history.
    const nameKey = state.creatorNameKey;
    if (session.slot !== 0 && !nameKey) return;
    rejoined = Date.now();
    const rk = state.rosterKey();
    const join: ControlRecord & { t: 'join' } = session.slot === 0 && rk && session.nameSecret
      ? { t: 'join', id: newRecordId(sodium), time: Date.now(), name: boxName(sodium, rk, session.name, id, 'member', 0), key: encodeKey(sodium, signPublic), box: encodeKey(sodium, first.publicKey),
        namekey: nameKeyOf(session.nameSecret) }
      : {
        t: 'join', id: newRecordId(sodium), time: Date.now(), key: encodeKey(sodium, signPublic), box: encodeKey(sodium, first.publicKey),
        name: sealName(sodium, session.name, nameKey!, { roomId: id, slot: session.slot, key: encodeKey(sodium, signPublic), box: encodeKey(sodium, first.publicKey) }),
      };
    if (session.joinProof) join.proof = session.joinProof;
    await control(join);
  };

  /**
   * For the creator: admits, for each invited place, the first join that
   * proves it came from that place's invite link, naming its signing key.
   * Members trust nobody else. Each admit is stored in this tab before it is
   * posted, and a place is admitted once, ever: an admit the history lacks
   * (its reply lost) is posted again with the same key, never another.
   */
  const postAdmit = async (slot: number, join: Member) => {
    const rk = state.rosterKey();
    const box = decodeKey(sodium, join.join.box);
    if (admitting.has(slot) || !rk || !box || join.name === '') return;
    admitting.add(slot);
    // One record per place, posted again unchanged if its reply was lost.
    // It hands them the roster key, sealed to their join's key, and their
    // name for everyone, now encrypted under the roster key.
    const record = admits.get(slot) ?? {
      t: 'admit', id: newRecordId(sodium), time: Date.now(), slot, key: join.join.key,
      roster: sealRoster(sodium, rk, box, id, slot), name: boxName(sodium, rk, join.name, id, 'member', slot),
    } satisfies ControlRecord;
    admits.set(slot, record);
    try {
      await exclusive(() => control(record));
      soon = true;
    } catch {
      admitting.delete(slot); // tried again on the next check
    }
  };
  /** Closes a place nobody should hold: here, on the server, then for everyone. */
  const closePlace = async (slot: number) => {
    removeHere(slot);
    try {
      if (owner !== null) await removeMember(id, owner, slot);
      await exclusive(() => control({ t: 'remove', id: newRecordId(sodium), time: Date.now(), slot }));
    } catch {
      // The creator can finish it in Members.
    }
  };
  const admitWaiting = async () => {
    // A second person proved they had the link for a place already let in:
    // the link leaked, and nobody can tell who is who. Close the place.
    for (const slot of state.contested) {
      if (contested.has(slot) || state.removed.has(slot)) continue;
      contested.add(slot);
      add(system('A second person used the invite for ', nameNode(slot), ' after they were let in, so the link was shared or leaked. Their place was closed: if they are who you meant, send them a new invite another way.'), false, false);
      void closePlace(slot);
    }
    for (const slot of state.badProof) {
      if (badProofShown.has(slot) || state.removed.has(slot) || state.admitSeen.has(slot)) continue;
      badProofShown.add(slot);
      // With a password, a failed proof may be a guess: close the place at
      // once, so each invite allows one try (also against a server that
      // posts joins for it).
      if (session.password) {
        add(system('Someone used the invite for ', nameNode(slot), ' with the wrong password, or a link that was changed on the way. Its place was closed, so nobody can try it again. If it was them, send a new invite.'), false, false);
        void closePlace(slot);
        continue;
      }
      add(system('Someone used the invite for ', nameNode(slot), ', but their link didn’t match the invite: it may have been changed on the way. They can’t be let in. Revoke that invite in Members and send a new one another way.'), false, false);
    }
    for (const k of session.known) {
      if (k.slot === 0 || state.admitSeen.has(k.slot) || state.removed.has(k.slot)) continue;
      const j = state.waitingJoin(k.slot, k.key) ?? state.members.get(k.slot);
      if (j && j.join.key === k.key) await postAdmit(k.slot, j);
    }
    for (const [slot, joins] of state.joinsToAdmit()) {
      if (session.known.some((k) => k.slot === slot) || state.removed.has(slot)) continue;
      const invite = session.invites.find((i) => i.slot === slot);
      if (!invite) continue;
      const valid = joins.filter((j) => proofOk(slot, j.join) === true);
      const m = valid[0];
      if (!m) continue;
      // The server stops an invite at its signed lifetime; this tab does
      // too, whatever the server does: a join it first sees well after the
      // invite expired is nobody it lets in (clocks and a sleeping tab get
      // ten minutes).
      if (Date.now() > invite.exp + INVITE_SLACK_MS) {
        if (!lateShown.has(slot)) {
          lateShown.add(slot);
          add(system('Someone used the invite for ', nameNode(slot), ' after it expired, so they weren’t let in and its place was closed. If it was them, send a new invite.'), false, false);
          void closePlace(slot);
        }
        continue;
      }
      // Never past the chat's own member limit. Counted from this tab's own
      // admits, which it pins before posting them: one pass may admit
      // several places before the history shows any of them.
      const pinned = new Set<number>([0, ...session.known.map((k) => k.slot)]);
      for (const r of state.removed) pinned.delete(r);
      const limit = session.settings?.max ?? MAX_SLOTS;
      if (Math.max(pinned.size, state.activeCount()) >= limit) {
        if (!lateShown.has(slot)) {
          lateShown.add(slot);
          add(system('The invite for ', nameNode(slot), ' was used, but the chat is full, so they weren’t let in and its place was closed.'), false, false);
          void closePlace(slot);
        }
        continue;
      }
      // Two different people with the link for one place: the link leaked,
      // and we cannot tell who is who. Let nobody in through it. (Every
      // join with a valid proof counts, also one whose name does not open.)
      if (valid.some((j) => j.join.key !== m.join.key)) {
        if (!contested.has(slot)) {
          contested.add(slot);
          add(system('Two different people used the invite for ', nameNode(slot), '. Nobody was let in with it, and its place was closed: send a new invite another way.'), false, false);
          void closePlace(slot);
        }
        continue;
      }
      // Its name must open (only the creator can read it): a join whose
      // name does not is nobody we can let in, and the place waits.
      if (m.name === '') continue;
      session.known.push({ slot, key: m.join.key });
      persist(); // pinned before it is posted
      await postAdmit(slot, m);
    }
  };

  /** Encrypts, signs and posts one chat record; it is applied here at once. */
  const sendChat = async (record: MessageRecord) => {
    if (ended) return;
    // Keys go to the members we know of. An old view may miss a new member
    // or a new receiving key: fetch the room again first.
    if (Date.now() - synced > STALE_MS) {
      await poll();
      if (Date.now() - synced > STALE_MS) throw new NotSynced();
    }
    let sent = false as boolean;
    let at: { gen: number; index: number } | undefined;
    await exclusive(async () => {
      await shareKeys();
      if (ended || !chain) return;
      // Sealing steps our chain past this record's key and deletes it.
      at = { gen: chain.gen, index: chain.index };
      const bytes = sealMessage(sodium, chain, id, session.slot, signSecret, record);
      session.sent++;
      persist();
      await post(bytes);
      sent = true;
    });
    if (!sent || ended) return;
    show(status, false);
    const e = state.applyOwn(record, at);
    if (e) show1(e, true);
    void poll();
  };
  const failed = (e: unknown, what: string) => {
    if (ended) return;
    if (e instanceof ApiError && e.status === 404) return gone();
    status.textContent = e instanceof NotSynced
      ? `Can’t reach the server right now. ${what} Try again in a moment.`
      : roomError(e, `${what} Check your connection and try again.`);
    show(status);
  };

  // --- Rendering. Every piece of text goes in with textContent. ---
  const nodes = new Map<string, HTMLLIElement>();
  // The replies to each message, so an edit touches only those.
  const repliesTo = new Map<Message, Set<Message>>();
  /** The run of bubbles the next message from the same person joins. */
  let run: { from: number; time: number; day: string; li: HTMLLIElement } | null = null;
  let lastDay = '';
  const dayOf = (t: number) => new Date(t).toDateString();
  const dayLabel = (t: number) => {
    const d = new Date(t).toDateString();
    if (d === new Date().toDateString()) return 'Today';
    if (d === new Date(Date.now() - 86_400_000).toDateString()) return 'Yesterday';
    return new Date(t).toLocaleDateString(undefined, { weekday: 'long', day: 'numeric', month: 'long' });
  };
  const at = (t: number) => new Date(t).toLocaleTimeString(undefined, { hour: 'numeric', minute: '2-digit' });
  // Senders set their own times. Shown times never run backwards and never
  // lie ahead of when the message arrived, so nobody can slip a message
  // under an earlier date or show a date to come.
  const shownAt = new Map<string, number>();
  let lastShown = 0;
  const timeOf = (m: Message) => shownAt.get(m.key) ?? m.time;
  const nameFor = (slot: number) => (slot === session.slot ? 'You' : state.nameOf(slot));
  /** True if we compared this member's safety code and their keys are still the ones we compared. */
  const isVerified = (slot: number) => {
    const m = state.members.get(slot);
    const k = session.verified.find((v) => v.slot === slot)?.key;
    return slot !== session.slot && m !== undefined && !m.removed && k !== undefined && k === encodeKey(sodium, m.signKey);
  };
  const setVerified = (slot: number, on: boolean) => {
    const m = state.members.get(slot);
    session.verified = session.verified.filter((v) => v.slot !== slot);
    if (on && m) session.verified.push({ slot, key: encodeKey(sodium, m.signKey) });
    persist();
    redrawNameNodes();
  };
  /**
   * Draws every name in the conversation again, in place: nothing else is
   * rebuilt, so focus stays put and screen readers do not hear the room again.
   */
  const redrawNameNodes = () => {
    log.setAttribute('aria-busy', 'true');
    for (const n of log.querySelectorAll<HTMLElement>('[data-name-slot]')) {
      n.replaceWith(nameNode(Number(n.dataset['nameSlot']), n.className, n.dataset['nameYou'] === '1'));
    }
    log.removeAttribute('aria-busy');
  };
  /** A name, with the start of its safety code as a badge when it could pass for someone else. */
  const nameNode = (slot: number, cls = 'nb-name', you = true): HTMLElement => {
    const n = make('span', cls);
    n.dataset['nameSlot'] = String(slot);
    n.dataset['nameYou'] = you ? '1' : '0';
    if (you && slot === session.slot) {
      n.textContent = 'You';
      return n;
    }
    // Before names can be read (or if one does not check out), the label or "Member N".
    const m = state.members.get(slot);
    n.append(document.createTextNode(m && m.name !== '' ? m.name : state.nameOf(slot)));
    if (isVerified(slot)) {
      const mark = icon('check');
      mark.classList.add('nb-verified');
      n.append(' ', mark, make('span', 'visually-hidden', ' (verified)'));
    }
    const tag = state.tagOf(slot);
    if (tag) {
      const badge = make('span', 'nb-tag', tag);
      badge.title = 'The start of their safety code: this name looks like another one in the chat.';
      n.append(' ', make('span', 'visually-hidden', 'safety code '), badge);
    }
    return n;
  };

  const empty = make('li', 'nb-chat-empty');
  empty.append(make('strong', '', 'No messages yet'),
    document.createTextNode(owner !== null
      ? 'Invite people with a link, then say hello. Only people in this chat can read it, not even the server.'
      : 'Say hello. Only people in this chat can read it, not even the server.'));
  if (owner !== null) {
    const invite = make('button', 'btn nb-btn-primary');
    invite.type = 'button';
    invite.append(icon('user-plus'), make('span', '', 'Invite people'));
    invite.addEventListener('click', () => el('room-invite-open').click());
    empty.append(make('br', ''), invite);
  }
  log.append(empty);

  // Scrolling: the page scrolls, like every other page. Stay at the newest
  // message unless the reader scrolled up.
  const page = document.scrollingElement ?? document.documentElement;
  const chatEl = el('room-chat');
  const topBar = document.querySelector<HTMLElement>('.nb-top');
  const head = chatEl.querySelector<HTMLElement>('.nb-chat-head')!;
  const dock = chatEl.querySelector<HTMLElement>('.nb-chat-dock')!;
  let atBottom = true;
  let pending = 0;
  const nearBottom = () => page.scrollHeight - page.scrollTop - window.innerHeight < 80;
  const toBottom = () => {
    window.scrollTo({ top: page.scrollHeight, behavior: 'instant' });
    atBottom = true;
  };
  const updateJump = () => {
    show(jump, !atBottom);
    jumpCount.textContent = pending > 99 ? '99+' : String(pending);
    show(jumpCount, pending > 0);
    jump.setAttribute('aria-label', pending > 0 ? `Go to the latest messages, ${pending} new` : 'Go to the latest messages');
  };
  window.addEventListener('scroll', () => {
    atBottom = nearBottom();
    if (atBottom) pending = 0;
    updateJump();
    closeMenu(false);
  }, { passive: true, signal: listening.signal });
  // The sticky header and dates sit under the site's bar; and a reply bar,
  // a growing message box or a turned phone must not hide the newest message.
  const sizes = new ResizeObserver(() => {
    // The site's bar stays at the top only on wider screens.
    const barStays = topBar !== null && getComputedStyle(topBar).position === 'sticky';
    chatEl.style.setProperty('--nb-top-h', `${barStays ? topBar.offsetHeight : 0}px`);
    chatEl.style.setProperty('--nb-head-h', `${head.offsetHeight}px`);
    if (atBottom) toBottom();
  });
  for (const n of [log, dock, head, topBar]) if (n) sizes.observe(n);
  jump.addEventListener('click', () => {
    window.scrollTo({ top: page.scrollHeight, behavior: window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth' });
    pending = 0;
    updateJump();
  });
  const add = (li: HTMLLIElement, mine: boolean, counts: boolean) => {
    const stick = mine || atBottom;
    log.append(li);
    if (stick) toBottom();
    else if (counts) pending++;
    updateJump();
  };

  /** A notice. Names go in their own element, so a name cannot pass for notice text. */
  const noticeParts = (li: HTMLLIElement, parts: (string | HTMLElement)[]) => {
    li.replaceChildren();
    for (const p of parts) {
      if (typeof p === 'string') li.append(p);
      else {
        p.classList.add('nb-sys-name');
        li.append(p);
      }
    }
  };
  const system = (...parts: (string | HTMLElement)[]) => {
    run = null;
    const li = make('li', 'nb-sys');
    noticeParts(li, parts);
    return li;
  };
  // Notices naming people are drawn again once names can be read (a new
  // member reads them only after being let in).
  const live: { li: HTMLLIElement; build: () => (string | HTMLElement)[] }[] = [];
  const systemLive = (build: () => (string | HTMLElement)[]) => {
    const li = system(...build());
    live.push({ li, build });
    return li;
  };
  let rosterShown = state.rosterVersion;
  const redrawNames = () => {
    if (state.rosterVersion === rosterShown) return;
    rosterShown = state.rosterVersion;
    log.setAttribute('aria-busy', 'true');
    for (const n of live) noticeParts(n.li, n.build());
    log.removeAttribute('aria-busy');
    redrawNameNodes();
    title.textContent = state.name || 'Null Chat';
    avatar.textContent = initial(state.name || 'Null Chat');
    updateMembers();
  };

  /** Whether the message a reply quotes was edited after the reply came. */
  const markEditedSince = (quote: HTMLElement, edited: HTMLElement, m: Message) => {
    const target = m.quote!.target!;
    const since = !target.deleted && target.text !== m.quote!.text;
    edited.hidden = !since;
    quote.setAttribute('aria-label', `Replying to ${nameFor(target.from)}${since ? ', a message edited since' : ''}. Show that message.`);
  };

  /** (Re)builds the inside of a message's list item. */
  const fill = (li: HTMLLIElement, m: Message) => {
    const own = m.from === session.slot;
    const name = nameFor(m.from);
    const face = make('div', `nb-m-avatar ${colour(m.from)}`, initial(state.nameOf(m.from)));
    face.setAttribute('aria-hidden', 'true');
    const bubble = make('div', 'nb-m-bubble');
    if (!own && li.classList.contains('nb-first')) bubble.append(nameNode(m.from, `nb-m-name ${colour(m.from)}`));
    else bubble.append(make('span', 'visually-hidden', `${name}:`));
    if (m.quote && !m.quote.target && !m.deleted) {
      // We never had the message, so whose it was is only the sender's
      // word: name nobody, or a member could pin words on anyone, you
      // included.
      bubble.append(make('span', 'nb-m-quote nb-m-quote-missing', 'Replying to a message you don’t have'));
    }
    if (m.quote?.target && !m.deleted) {
      // The quote is what the target said when the reply arrived.
      const q = m.quote;
      const target = q.target!;
      const quote = make('button', 'nb-m-quote');
      quote.type = 'button';
      const quoted = make('span', '', target.deleted ? 'Unsent message' : q.text ?? '');
      quoted.dir = 'auto';
      const who = make('strong', '');
      who.append(nameNode(target.from));
      quote.append(who, quoted);
      const edited = make('span', 'nb-m-quote-edited', 'Edited since');
      quote.append(edited);
      markEditedSince(quote, edited, m);
      quote.addEventListener('click', () => {
        const n = nodes.get(target.key);
        if (!n) return;
        n.scrollIntoView({ block: 'center', behavior: window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth' });
        n.classList.remove('nb-flash');
        void n.offsetWidth;
        n.classList.add('nb-flash');
      });
      bubble.append(quote);
    }
    // The time (and "(edited)") floats at the end of the last line of
    // text, and drops below it only when the line is full.
    const meta = make('span', 'nb-m-meta');
    if (m.edited && !m.deleted) meta.append(make('span', 'nb-m-edited', '(edited) '));
    const t = timeOf(m);
    const time = make('time', '', at(t));
    time.dateTime = new Date(t).toISOString();
    time.title = new Date(t).toLocaleString(undefined, { dateStyle: 'full', timeStyle: 'short' });
    meta.append(time);
    const body = make('p', m.deleted ? 'nb-m-gone' : 'nb-m-text');
    body.append(make('span', 'nb-m-words', m.deleted ? (own ? 'You unsent this message.' : 'This message was unsent.') : m.text));
    body.dir = 'auto';
    bubble.append(body);
    const reacted = REACTIONS.filter((emoji) => (m.reactions.get(emoji)?.size ?? 0) > 0);
    if (reacted.length > 0 && !m.deleted) {
      // Reactions get their own row, with the time beside them.
      const list = make('ul', 'nb-m-reacts');
      list.setAttribute('aria-label', 'Reactions');
      for (const emoji of reacted) {
        const who = m.reactions.get(emoji)!;
        const mine = who.has(session.slot);
        const b = make('button', 'nb-react');
        b.type = 'button';
        b.setAttribute('aria-pressed', String(mine));
        const emojiSpan = make('span', 'nb-react-emoji', emoji);
        emojiSpan.setAttribute('aria-hidden', 'true');
        b.append(emojiSpan, make('span', '', String(who.size)));
        const names = [...who].map(nameFor).join(', ');
        b.title = names;
        b.setAttribute('aria-label', `${emoji} ${who.size}: ${names}. ${mine ? 'Take back your reaction' : 'React with this too'}`);
        b.addEventListener('click', () => react(m, emoji, !mine));
        const item = make('li', '');
        item.append(b);
        list.append(item);
      }
      const foot = make('div', 'nb-m-foot');
      foot.append(list, meta);
      bubble.append(foot);
    } else {
      body.append(meta);
    }
    li.replaceChildren(face, bubble);
    if (!m.deleted) {
      const more = make('button', 'nb-m-more');
      more.type = 'button';
      more.setAttribute('aria-label', `Options for ${own ? 'your message' : `${name}’s message`}`);
      more.setAttribute('aria-haspopup', 'menu');
      more.setAttribute('aria-expanded', 'false');
      more.append(icon('more'));
      more.addEventListener('click', () => {
        if (menuFor?.id === m.key) return closeMenu(true);
        const r = more.getBoundingClientRect();
        openMenu(m, own ? r.left : r.right, r.top, more);
      });
      li.append(more);
    }
  };
  const react = (m: Message, emoji: string, on: boolean) => {
    sendChat({ t: 'react', id: newRecordId(sodium), time: Date.now(), target: m.id, author: m.from, emoji, on }).catch((e) => failed(e, 'The reaction was not sent.'));
  };
  const messageOf = (n: EventTarget | null): Message | undefined => {
    const li = n instanceof Element ? n.closest<HTMLLIElement>('.nb-m') : null;
    const mid = li?.dataset['id'];
    return mid ? state.message(mid) : undefined;
  };

  // --- The message menu: reactions, then Reply, Copy, Edit and Unsend. ---
  // Right-click, a long press, the ⋯ button beside the bubble, or the
  // keyboard's menu key open it. It never covers the conversation for longer
  // than it is open.
  const menu = make('div', 'nb-menu');
  menu.setAttribute('role', 'menu');
  menu.setAttribute('aria-label', 'Message options');
  menu.hidden = true;
  document.body.append(menu);
  let menuFor: { id: string; opener: HTMLElement | null } | null = null;
  const closeMenu = (refocus: boolean) => {
    if (!menuFor) return;
    const opener = menuFor.opener;
    menuFor = null;
    menu.hidden = true;
    menu.replaceChildren();
    document.removeEventListener('pointerdown', outside, true);
    opener?.setAttribute('aria-expanded', 'false');
    if (refocus && opener?.isConnected) opener.focus();
  };
  const outside = (ev: Event) => {
    if (!menu.contains(ev.target as Node)) closeMenu(false);
  };
  const menuItem = (label: string, iconName: string, run: (b: HTMLButtonElement) => void, danger = false) => {
    const b = make('button', danger ? 'nb-menu-item nb-danger' : 'nb-menu-item');
    b.type = 'button';
    b.setAttribute('role', 'menuitem');
    b.append(icon(iconName), make('span', '', label));
    noRepeat(b); // holding Enter must not confirm a two-step item
    b.addEventListener('click', () => run(b));
    return b;
  };
  const openMenu = (m: Message, x: number, y: number, opener: HTMLElement | null) => {
    closeMenu(false);
    if (ended || m.deleted || composerLocked) return;
    menuFor = { id: m.key, opener };
    const own = m.from === session.slot;
    const row = make('div', 'nb-menu-reacts');
    row.setAttribute('role', 'group');
    row.setAttribute('aria-label', 'React');
    for (const emoji of REACTIONS) {
      const mine = m.reactions.get(emoji)?.has(session.slot) ?? false;
      const b = make('button', '', emoji);
      b.type = 'button';
      b.setAttribute('role', 'menuitemcheckbox');
      b.setAttribute('aria-checked', String(mine));
      b.addEventListener('click', () => {
        closeMenu(true);
        react(m, emoji, !mine);
      });
      row.append(b);
    }
    menu.replaceChildren(row,
      menuItem('Reply', 'reply', () => {
        closeMenu(false);
        startContext('reply', m);
      }),
      menuItem('Copy text', 'copy', async () => {
        closeMenu(true);
        if (await copyText(m.text)) announce('Message copied.');
      }));
    if (own) {
      menu.append(
        menuItem('Edit', 'edit', () => {
          closeMenu(false);
          startContext('edit', m);
        }),
        menuItem('Unsend', 'trash', (b) => {
          // Two steps: unsending removes it for everyone.
          if (!b.classList.contains('nb-armed')) {
            b.classList.add('nb-armed');
            b.dataset['armed'] = String(Date.now());
            b.querySelector('span')!.textContent = 'Unsend for everyone?';
            return;
          }
          if (Date.now() - Number(b.dataset['armed']) < CONFIRM_GAP_MS) return; // a double-click does not confirm
          closeMenu(true);
          sendChat({ t: 'unsend', id: newRecordId(sodium), time: Date.now(), target: m.id }).catch((e) => failed(e, 'The message was not unsent.'));
        }, true));
    }
    menu.hidden = false;
    opener?.setAttribute('aria-expanded', 'true');
    // Next to the pointer or the button, inside the window.
    const w = menu.offsetWidth;
    const h = menu.offsetHeight;
    const left = Math.max(8, Math.min(opener && own ? x - w : x, window.innerWidth - w - 8));
    const top = y + h + 8 > window.innerHeight ? Math.max(8, y - h) : y;
    menu.style.left = `${left}px`;
    menu.style.top = `${top}px`;
    document.addEventListener('pointerdown', outside, true);
    menu.querySelector<HTMLButtonElement>('.nb-menu-item')?.focus();
  };
  menu.addEventListener('keydown', (e) => {
    const items = [...menu.querySelectorAll<HTMLButtonElement>('button')];
    const i = items.indexOf(document.activeElement as HTMLButtonElement);
    const go = (j: number) => items[(j + items.length) % items.length]?.focus();
    if (e.key === 'Escape') closeMenu(true);
    else if (e.key === 'Tab') closeMenu(false);
    else if (e.key === 'ArrowDown' || e.key === 'ArrowRight') go(i + 1);
    else if (e.key === 'ArrowUp' || e.key === 'ArrowLeft') go(i - 1);
    else if (e.key === 'Home') go(0);
    else if (e.key === 'End') go(items.length - 1);
    else return;
    if (e.key !== 'Tab') e.preventDefault();
  });
  window.addEventListener('resize', () => closeMenu(false), { signal: listening.signal });
  window.addEventListener('blur', () => closeMenu(false), { signal: listening.signal });

  // Right-click (and Android's long press): our menu, unless some text is
  // selected, which keeps the browser's own menu for copying part of it.
  let pressed = 0; // when a long press last opened the menu
  log.addEventListener('contextmenu', (ev) => {
    const m = messageOf(ev.target);
    if (!m || m.deleted || !(ev.target as Element).closest('.nb-m-bubble, .nb-m-more')) return;
    if (String(window.getSelection() ?? '') !== '' && Date.now() - pressed > 800) return;
    ev.preventDefault();
    if (Date.now() - pressed < 800) return;
    const opener = (ev.target as Element).closest<HTMLElement>('.nb-m')?.querySelector<HTMLElement>('.nb-m-more') ?? null;
    if (ev.button === -1 || (ev.clientX === 0 && ev.clientY === 0)) {
      // From the keyboard: next to the message's ⋯ button.
      const r = (opener ?? (ev.target as Element)).getBoundingClientRect();
      openMenu(m, m.from === session.slot ? r.left : r.right, r.top, opener);
    } else {
      openMenu(m, ev.clientX, ev.clientY, null);
    }
  });
  // A long press on touch screens (iPhones send no contextmenu event).
  let press = 0;
  let pressStart: { x: number; y: number } | null = null;
  const cancelPress = () => {
    clearTimeout(press);
    press = 0;
  };
  log.addEventListener('pointerdown', (ev) => {
    if (ev.pointerType !== 'touch') return;
    const target = ev.target as Element;
    if (!target.closest('.nb-m-bubble') || target.closest('button')) return;
    const m = messageOf(target);
    if (!m || m.deleted) return;
    pressStart = { x: ev.clientX, y: ev.clientY };
    cancelPress();
    press = window.setTimeout(() => {
      press = 0;
      pressed = Date.now();
      window.getSelection()?.removeAllRanges();
      openMenu(m, pressStart!.x, pressStart!.y, null);
    }, LONG_PRESS_MS);
  });
  log.addEventListener('pointermove', (ev) => {
    if (press && pressStart && Math.hypot(ev.clientX - pressStart.x, ev.clientY - pressStart.y) > 10) cancelPress();
  });
  for (const t of ['pointerup', 'pointercancel', 'pointerleave'] as const) log.addEventListener(t, cancelPress);
  // A double-click on a bubble replies to it, as in desktop messengers.
  log.addEventListener('dblclick', (ev) => {
    const target = ev.target as Element;
    if (!target.closest('.nb-m-bubble') || target.closest('button')) return;
    const m = messageOf(target);
    if (!m || m.deleted || composerLocked) return;
    window.getSelection()?.removeAllRanges();
    startContext('reply', m);
  });

  /** Shows one event: a new message, a change to one, or a notice. */
  const show1 = (e: RoomEvent, mine: boolean) => {
    switch (e.kind) {
      case 'message': {
        const m = e.message;
        // Not before the room was created, nor before the message above.
        // Nor before we joined: nothing we can read was sent earlier.
        const t = Math.max(lastShown, Math.min(state.createdAt ?? 0, Date.now()), Math.min(state.members.get(session.slot)?.joinedAt ?? 0, Date.now()), Math.min(m.time, Date.now()));
        lastShown = t;
        shownAt.set(m.key, t);
        const day = dayOf(t);
        if (day !== lastDay) {
          lastDay = day;
          run = null;
          add(make('li', 'nb-day', dayLabel(t)), mine, false);
        }
        empty.remove();
        const li = make('li', m.from === session.slot ? 'nb-m nb-own nb-last' : 'nb-m nb-last');
        li.dataset['id'] = m.key; // a slot number and a validated 32-hex-digit id
        if (run && run.from === m.from && t - run.time < GROUP_MS) run.li.classList.remove('nb-last');
        else li.classList.add('nb-first');
        run = { from: m.from, time: t, day, li };
        fill(li, m);
        nodes.set(m.key, li);
        if (m.quote?.target) {
          const set = repliesTo.get(m.quote.target) ?? new Set<Message>();
          set.add(m);
          repliesTo.set(m.quote.target, set);
        }
        add(li, mine, !mine);
        if (!mine && document.hidden) unread++;
        return;
      }
      case 'updated': {
        const li = nodes.get(e.message.key);
        if (li) fill(li, e.message);
        // Replies quoting it say it was edited since, or unsent. An edit
        // only flips a label in place: a member who edits one message many
        // times must not make every tab rebuild every reply each time.
        const replies = repliesTo.get(e.message);
        if (replies) {
          for (const other of replies) {
            const n = nodes.get(other.key);
            if (!n) continue;
            const quote = n.querySelector<HTMLElement>('.nb-m-quote');
            const edited = quote?.querySelector<HTMLElement>('.nb-m-quote-edited');
            if (e.message.deleted || !quote || !edited) fill(n, other);
            else markEditedSince(quote, edited, other);
          }
          if (e.message.deleted) repliesTo.delete(e.message);
        }
        if (e.message.deleted && e.message.quote?.target) repliesTo.get(e.message.quote.target)?.delete(e.message);
        if (mode?.target === e.message) {
          if (e.message.deleted) stopContext();
          else el('room-context-quote').textContent = e.message.text;
        }
        if (menuFor?.id === e.message.key && e.message.deleted) closeMenu(false);
        return;
      }
      case 'joined':
        if (e.member.slot === session.slot) {
          add(system(session.slot === 0 ? 'You created this chat. Messages in it are end-to-end encrypted.' : 'You joined. Messages from now on are end-to-end encrypted.'), mine, false);
        } else {
          const slot = e.member.slot;
          add(systemLive(() => {
            const as = state.invitedAs(slot);
            return slot === 0 ? [nameNode(0), ' created this chat.']
              : as ? [nameNode(slot), ' joined, with the invite made for ', make('span', '', as), '.'] : [nameNode(slot), ' joined.'];
          }), mine, false);
        }
        updateMembers();
        return;
      case 'removed': {
        const slot = e.slot;
        add(systemLive(() => [nameNode(slot), ' was removed.']), mine, false);
        updateMembers();
        return;
      }
      case 'renamed':
        title.textContent = e.name || 'Null Chat';
        avatar.textContent = initial(e.name || 'Null Chat');
        return;
      default:
        return;
    }
  };
  const updateMembers = () => {
    const n = [...state.members.values()].filter((m) => !m.removed).length;
    el('room-member-count').textContent = `${n} ${n === 1 ? 'member' : 'members'}`;
  };

  // "self-destructs in 23h 59m"; on phones a flame and the time.
  const expires = el('room-expires');
  const expiresLabel = make('span', 'nb-wide');
  const expiresLeft = make('span', '');
  expires.replaceChildren(icon('flame'), expiresLabel, expiresLeft);
  const updateCountdown = () => {
    if (deadline === null) return;
    const left = deadline - Date.now();
    expiresLabel.textContent = left > 0 ? 'Self-destructs in ' : 'Self-destructing ';
    expiresLeft.textContent = left > 0 ? formatCountdown(left) : 'now';
    expires.title = left > 0 ? `This chat self-destructs in ${formatCountdown(left)}` : '';
  };
  const countdown = window.setInterval(updateCountdown, 1000);

  // --- Fetching ---
  let soon = false; // check again shortly, to show what we just posted
  const schedule = () => {
    clearTimeout(timer);
    const wait = soon ? 400 : document.hidden ? HIDDEN_POLL_MS : VISIBLE_POLL_MS;
    soon = false;
    if (!ended) timer = window.setTimeout(() => void poll(), wait);
  };
  let polling: Promise<void> | null = null;
  /** Fetches and applies everything new; callers share a fetch in progress. */
  function poll(): Promise<void> {
    if (ended) return Promise.resolve();
    polling ??= fetchAll().finally(() => {
      polling = null;
    });
    return polling;
  }
  async function fetchAll(): Promise<void> {
    let delay: number | null = null;
    // Old receiving keys go before anything is read, also after the tab
    // was asleep, and their deletion is saved at once, even if the fetch
    // then fails.
    dropRetired();
    persist();
    try {
      for (;;) {
        const batch = await fetchRecords(id, session.member, after);
        if (ended) return;
        // The countdown is the server's; it never runs past the end the
        // creator signed. Only a gap bigger than clocks usually have is
        // worth a warning.
        fetchedAt = Date.now();
        deadline = fetchedAt + batch.expiresIn * 1000;
        if (state.ends !== null && deadline > state.ends) {
          if (deadline > state.ends + ENDS_SLACK_MS && !warnedEnds) {
            warnedEnds = true;
            add(system('The server and the chat’s creator disagree on when this chat ends, by more than clocks usually do. The countdown shows the earlier time.'), false, false);
          }
          deadline = state.ends;
        }
        updateCountdown();
        for (const r of batch.records) {
          const e = state.apply(r.from, r.data);
          if (e?.kind === 'removed' && e.slot !== session.slot) session.rotate = true; // they must not get our next keys
          if (e) show1(e, false);
        }
        after = batch.next;
        redrawNames();
        if (state.conflict || state.cloned) break;
        // Chains stepped past messages read are saved as we go.
        persist();
        if (batch.records.length === 0 || batch.next >= 1000) break;
      }
      // Any delivery opened with our current key: replace that key soon.
      if (state.deliveredMax >= currentBox()) session.boxRotate = true;
      // Messages we cannot read, newer than the first fetch, may mean the
      // server is hiding deliveries sealed to our current key: replace it.
      if (unreadableBase === null) unreadableBase = state.unreadable;
      else if (state.unreadable > unreadableBase) {
        session.boxRotate = true;
        unreadableBase = state.unreadable;
      }
      if (state.conflict) {
        end('This chat’s history was changed', 'The server showed this tab a different history of the chat than before (other keys for someone, or a removal undone). Someone may be trying to listen in. Leave this chat and tell the others.');
        return;
      }
      for (const [slot, kind] of state.forks) {
        if (warnedForks.has(`${kind}:${slot}`)) continue;
        warnedForks.add(`${kind}:${slot}`);
        add(kind === 'keys'
          ? system(nameNode(slot), ' gave different people different keys, so they can show each of you different messages. Remove them, or leave the chat.')
          : system(nameNode(slot), '’s messages and keys arrived out of order: they, or the server, may be showing people different conversations. Compare with the others another way, and leave if in doubt.'), false, false);
      }
      for (const slot of state.skipped(SKIPPED_MS)) {
        if (warnedForks.has(`skipped:${slot}`)) continue;
        warnedForks.add(`skipped:${slot}`);
        add(system('Keys from ', nameNode(slot), ' keep going to others but not to you: they, or the server, are leaving you out. Compare safety codes, and leave if in doubt.'), false, false);
      }
      for (const note of state.forkNotes) {
        // Whose message the receipt is about is the claimer's choice too,
        // so the notice names only the claimer.
        const claimer = Number(note.split(':')[0]);
        if (warnedForks.has(`receipts:${claimer}`)) continue;
        warnedForks.add(`receipts:${claimer}`);
        add(system(nameNode(claimer), '’s read receipts don’t match the conversation you saw. Either their receipts are false, or someone, maybe with the server’s help, is showing people different conversations. Compare with the others another way, and leave if in doubt.'), false, false);
      }
      // Every room has a signed room record (its name and end), right after
      // the creator's join: a history without it was cut.
      if (state.members.has(0) && state.ends === null && !warnedNoRoom && after > 1) {
        warnedNoRoom = true;
        add(system('This chat’s signed settings are missing from what the server sent. The server may be hiding records; the countdown is only its word.'), false, false);
      }
      for (const slot of state.staleFrom) {
        if (warnedForks.has(`stale:${slot}`)) continue;
        warnedForks.add(`stale:${slot}`);
        add(system(nameNode(slot), ' sent you keys locked to an old receiving key of yours, one you had replaced well before. Either the server hid your newer key from them, or they did this on purpose. Compare safety codes in Members, and leave if in doubt.'), false, false);
      }
      if (state.cloned) {
        end('This chat is open somewhere else', 'A copy of this tab’s keys posted in this chat: a copied tab, an older copy of this tab that the browser restored, or someone who copied your browser data. This tab’s copy of the keys has been deleted. If you didn’t do this, tell the others to leave the chat.');
        return;
      }
      persist();
      if (unread > 0) document.title = `(${unread}) ${baseTitle}`;
      show(status, false);
      if (state.removed.has(session.slot)) {
        if (!state.members.has(session.slot)) {
          end('You weren’t let in', state.passwordRequired
            ? 'The person who invited you closed your place without letting you in: the password may have been wrong, the invite may have expired or been revoked, or someone else used it too. Ask them for a new invite, and check the password with them.'
            : 'The person who invited you closed your place before letting you in: the invite may have expired or been revoked, or someone else used it too. Ask them for a new invite, sent another way.');
          return;
        }
        end('You were removed from this Null Chat', 'The person who created it removed you. You can no longer read or post in it.');
        return;
      }
      if (state.inviteMismatch) {
        end('This invite link was damaged', 'The link you used is not the one the chat’s creator made: part of it was changed on the way, so they can’t let you in. Ask them for a new invite, and send it a different way if you can.');
        return;
      }
      if (state.impostor()) {
        end('Someone else took your place in this chat', 'The chat shows keys for your place that are not yours, so someone who has the chat’s key, working with the server, may be posing as you. Leave this chat and tell the person who invited you.');
        return;
      }
      // Admits past the chat's signed member limit: this tab let nobody in.
      for (const slot of state.overLimit) {
        if (overLimitShown.has(slot)) continue;
        overLimitShown.add(slot);
        add(system('The creator’s app let ', nameNode(slot), ` in past this chat’s limit of ${state.maxMembers ?? '?'} people, so this tab didn’t. Only the creator’s key can do that: their app or the server may have been tampered with.`), false, false);
      }
      if (session.slot === 0) await admitWaiting();
      if (!state.members.has(session.slot)) {
        if (state.waitingForAdmit()) {
          const creator = state.members.get(0)?.name || 'the chat’s creator';
          text.placeholder = `Waiting for ${creator} to let you in…`;
          waitingSince ??= Date.now();
          const code = safetyCode(sodium, signPublic);
          status.textContent = Date.now() - waitingSince < WAIT_HINT_MS
            ? `Waiting for ${creator} to let you in. Their tab does it while the chat is open. Your safety code is ${code}.`
            : `Still waiting. The creator’s tab lets people in while the chat is open there. If they say you’re in already, someone else may have used your invite: ask them to check Members for your safety code, ${code}.`;
          show(status);
        } else {
          await exclusive(rejoin); // our join announcement was lost: send it again
        }
      } else {
        await exclusive(rotateReceiving);
        await exclusive(shareKeys);
        // As fresh as the fetch, not as the end of this check (a tab can be
        // frozen in between).
        synced = fetchedAt;
        // Only now can anyone read what we send.
        if (composerLocked) unlockComposer();
      }
    } catch (e) {
      if (ended) return;
      if (e instanceof ApiError && e.status === 404) {
        gone();
        return;
      }
      if (e instanceof ApiError && e.status === 429) {
        // Many people on one network share its limit: slow down.
        status.textContent = 'Lots of activity from your network. Checking for messages a little less often…';
        delay = 10_000;
      } else if (e instanceof ApiError && e.status === 409) {
        status.textContent = 'This chat is full, so nothing more can be posted in it. Self-destruct it and start a new one.';
      } else {
        status.textContent = 'Can’t reach the server right now. Retrying…';
      }
      show(status);
    }
    if (ended) return;
    if (delay !== null) {
      clearTimeout(timer);
      timer = window.setTimeout(() => void poll(), delay);
    } else {
      schedule();
    }
  }
  document.addEventListener('visibilitychange', () => {
    if (!document.hidden && !ended) {
      unread = 0;
      document.title = baseTitle;
      void poll();
    }
  }, { signal: listening.signal });
  // Leaving the page (for another page in this tab, or closing it) clears
  // the conversation and every key from it, as a reload would, so a page
  // the browser keeps in its back/forward cache cannot bring them back. The
  // session stays: coming back reloads and rejoins, showing new messages only.
  let leftLive = false;
  window.addEventListener('pagehide', () => {
    if (ended) return;
    leftLive = true;
    shutdown();
  }, { signal: listening.signal });
  window.addEventListener('pageshow', (e) => { if (e.persisted && leftLive) location.reload(); });
  if (navigator.locks) {
    void navigator.locks.request(lockName, { ifAvailable: true }, (lock) => {
      if (!lock) {
        refuse();
        return undefined;
      }
      if (ended) return undefined;
      start();
      return new Promise<void>((resolve) => {
        releaseLock = resolve;
      });
    }).catch(() => refuse());
  } else {
    // Older browsers: ask other tabs. The tab opened first answers, and only
    // an answer from an older tab stops this one.
    const opened = Date.now();
    try {
      channel = new BroadcastChannel(lockName);
      channel.onmessage = (ev: MessageEvent<unknown>) => {
        if (ended) return;
        const m = (typeof ev.data === 'object' && ev.data !== null ? ev.data : {}) as Record<string, unknown>;
        if (typeof m['opened'] !== 'number') return;
        if (m['type'] === 'hello' && m['opened'] > opened) channel?.postMessage({ type: 'taken', opened });
        if (m['type'] === 'taken' && m['opened'] < opened) refuse();
      };
      channel.postMessage({ type: 'hello', opened });
    } catch {
      // No BroadcastChannel: nothing to coordinate with.
    }
    timer = window.setTimeout(start, 500);
  }

  // --- Composing: replies and edits show above the box. ---
  // Until our keys have reached the room, a message would be unreadable to
  // everyone: the box opens after the first complete sync.
  let composerLocked = true;
  let sending = false;
  text.disabled = true;
  text.placeholder = 'Connecting…';
  const updateSend = () => {
    send.disabled = composerLocked || sending || text.value.trim() === '';
  };
  updateSend();
  function unlockComposer(): void {
    if (ended) return;
    composerLocked = false;
    text.disabled = false;
    text.placeholder = 'Write a message…';
    updateSend();
    const focus = document.activeElement;
    if (desktop && (focus === document.body || focus === title || focus === null)) text.focus({ preventScroll: true });
  }
  // The box grows with its text, up to a few lines (CSS does it where
  // field-sizing works; this is for the other browsers).
  const grow = () => {
    if (CSS.supports('field-sizing', 'content')) return;
    text.style.height = 'auto';
    text.style.height = `${Math.min(text.scrollHeight, 168)}px`;
  };
  text.addEventListener('input', () => {
    updateSend();
    grow();
  });
  let mode: { kind: 'reply' | 'edit'; target: Message } | null = null;
  text.maxLength = MAX_MESSAGE_LENGTH;
  const startContext = (kind: 'reply' | 'edit', target: Message) => {
    if (target.deleted || composerLocked) return;
    if (mode?.kind === 'edit' && kind !== 'edit') text.value = '';
    mode = { kind, target };
    el('room-context-title').textContent = kind === 'edit' ? 'Edit message' : `Reply to ${target.from === session.slot ? 'yourself' : state.nameOf(target.from)}`;
    el('room-context-quote').textContent = target.text;
    context.querySelector('use')?.setAttribute('href', kind === 'edit' ? '#i-edit' : '#i-reply');
    show(context);
    if (kind === 'edit') text.value = target.text;
    updateSend();
    grow();
    text.focus({ preventScroll: true });
    text.setSelectionRange(text.value.length, text.value.length);
  };
  const stopContext = () => {
    if (mode?.kind === 'edit') text.value = '';
    mode = null;
    show(context, false);
    updateSend();
    grow();
  };
  el('room-context-cancel').addEventListener('click', () => {
    stopContext();
    text.focus({ preventScroll: true });
  });
  text.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey && !e.isComposing) {
      e.preventDefault();
      composer.requestSubmit();
    } else if (e.key === 'Escape' && mode) {
      e.preventDefault();
      stopContext();
    } else if (e.key === 'ArrowUp' && text.value === '' && !mode) {
      // Like most chat apps: edit your last message.
      const mine = [...state.messages].reverse().find((m) => m.from === session.slot && !m.deleted);
      if (mine) {
        e.preventDefault();
        startContext('edit', mine);
      }
    }
  });
  composer.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    // Control and direction characters, stacks of marks and long runs of
    // blank lines are dropped: others refuse messages that have them.
    let value = cleanText(text.value);
    if (value.length > MAX_MESSAGE_LENGTH) value = cleanText(value.slice(0, MAX_MESSAGE_LENGTH));
    if (ended || sending || composerLocked) return;
    if (value === '') {
      if (mode?.kind === 'edit') stopContext();
      return;
    }
    const current = mode;
    if (current && current.target.deleted) {
      stopContext();
      return;
    }
    sending = true;
    updateSend();
    composer.setAttribute('aria-busy', 'true');
    try {
      if (current?.kind === 'edit') {
        if (value !== current.target.text) await sendChat({ t: 'edit', id: newRecordId(sodium), time: Date.now(), target: current.target.id, text: value });
      } else {
        // Receipts: the newest place read from each member, so others can
        // see whether they read the same.
        await sendChat({ t: 'msg', id: newRecordId(sodium), time: Date.now(), text: value, reply: current?.kind === 'reply' ? { id: current.target.id, author: current.target.from } : null, seen: state.acks() });
      }
      if (ended) return;
      text.value = '';
      mode = null;
      show(context, false);
      grow();
    } catch (e) {
      failed(e, current?.kind === 'edit' ? 'Your edit was not saved.' : 'Your message was not sent; it’s still in the box.');
    } finally {
      sending = false;
      updateSend();
      composer.removeAttribute('aria-busy');
      if (!ended) text.focus({ preventScroll: true });
    }
  });

  const isEnded = () => ended;
  // A removal counts in this tab at once, before the server or the room
  // hears of it: no keys or admits for that place from here on.
  const removeHere = (slot: number) => {
    state.removeLocally(slot);
    session.rotate = true;
    persist();
  };
  initMembers(sodium, id, session, state, control, gone, isEnded, removeHere, nameNode, poll, isVerified, setVerified, listening.signal);
  // Revoking an invite closes its place like a removal: on the server
  // first (the link stops working), then for everyone, signed.
  const revokePlace = async (slot: number) => {
    removeHere(slot);
    await removeMember(id, owner!, slot);
    if (!state.removalSeen.has(slot)) await control({ t: 'remove', id: newRecordId(sodium), time: Date.now(), slot });
  };
  if (owner !== null) initOwner(sodium, id, session, owner, control, gone, signPublic, isEnded, state, listening.signal, revokePlace);
  // (Invites made in this tab add their secrets to the session; persist()
  // saves them with everything else.)
  initDestroy(id, session, end, listening.signal);
}

/** Anyone in the room can self-destruct it, after confirming in a dialog. */
function initDestroy(id: string, session: Session, end: (heading: string, text: string) => void, signal: AbortSignal): void {
  const dialog = el<HTMLDialogElement>('room-destroy-dialog');
  const confirm = el<HTMLButtonElement>('room-destroy-confirm');
  const error = el('room-destroy-error');
  el('room-destroy').addEventListener('click', () => {
    show(error, false);
    dialog.showModal();
  }, { signal });
  for (const b of ['room-destroy-close', 'room-destroy-cancel']) el(b).addEventListener('click', () => dialog.close(), { signal });
  confirm.addEventListener('click', async () => {
    if (confirm.disabled) return;
    show(error, false);
    const done = busy(confirm, 'Self-destructing…');
    try {
      await destroyRoom(id, session.member);
      done();
      end('Null Chat destroyed', 'It’s gone for everyone, with all its messages.');
    } catch (e) {
      done();
      if (e instanceof ApiError && e.status === 404) {
        end('This Null Chat has ended', 'It self-destructed, expired, or the server restarted, or you were removed.');
        return;
      }
      error.textContent = roomError(e, 'The chat could not be self-destructed. Check your connection and try again.');
      show(error);
    }
  }, { signal });
}

function initMembers(sodium: Sodium, id: string, session: Session, state: RoomState, control: (r: ControlRecord) => Promise<void>, gone: () => void, isEnded: () => boolean,
  removeHere: (slot: number) => void, nameNode: (slot: number, cls?: string, you?: boolean) => HTMLElement, sync: () => Promise<void>,
  isVerified: (slot: number) => boolean, setVerified: (slot: number, on: boolean) => void, signal: AbortSignal): void {
  const dialog = el<HTMLDialogElement>('room-members-dialog');
  const list = el('room-member-list');
  const error = el('room-members-error');
  const render = async () => {
    show(error, false);
    let states: Map<number, SlotState> | null = null;
    if (session.owner !== null) {
      try {
        states = await fetchMembers(id, session.owner);
      } catch (e) {
        if (isEnded()) return;
        if (e instanceof ApiError && e.status === 404) return gone();
        error.textContent = 'The member list could not be loaded. Try again in a moment.';
        show(error);
      }
    }
    if (isEnded()) return;
    const slots = new Set<number>([...state.members.keys(), ...(states?.keys() ?? [])]);
    list.replaceChildren(...[...slots].sort((a, b) => a - b).map((slot) => {
      const m = state.members.get(slot);
      // Removed for everyone only once the creator's signed removal is in
      // the room's history; the server's word, or this tab's, is not enough.
      const announced = state.removalSeen.has(slot);
      const closed = states?.get(slot) === 'removed';
      const started = announced || closed || state.removed.has(slot);
      const li = document.createElement('li');
      const face = make('div', `nb-m-avatar ${colour(slot)}`, initial(state.nameOf(slot)));
      face.setAttribute('aria-hidden', 'true');
      const name = nameNode(slot, 'nb-member-name', false);
      if (slot === session.slot) name.append(' (you)');
      const as = state.invitedAs(slot);
      const verified = isVerified(slot);
      // The safety code always shows: what the server says about a place
      // must not hide it.
      const code = m ? ` · Code ${m.code}` : '';
      const detail = make('span', 'nb-member-detail',
        announced ? (m ? `Removed${code}` : 'Invite revoked') : started ? `Removal not finished: they may still get messages${code}` :
          m ? `${verified ? 'Verified · ' : ''}${slot === 0 ? 'Created the chat · ' : ''}${as ? `Used the invite made for ${as} · ` : ''}Code ${m.code}` :
            states?.get(slot) === 'expired' ? 'Invite expired unused' :
              state.badProof.has(slot) ? 'Joined with a link that didn’t match the invite: can’t be let in' :
                states?.get(slot) === 'joined' ? 'Joined, not let in yet' : 'Invited, hasn’t joined yet');
      if (!m && state.badProof.has(slot)) detail.classList.add('nb-tone-warn');
      if (started && !announced) detail.classList.add('nb-tone-warn');
      detail.title = m ? 'Compare this code with the one they see, in person or on a call.' : '';
      li.append(face, name, detail);
      const actions = make('div', 'nb-member-actions');
      li.append(actions);
      // After comparing codes in person or on a call, mark them verified:
      // their name then shows a check, which no name can imitate.
      if (m && slot !== session.slot && !announced) {
        const check = make('button', 'btn nb-btn-secondary nb-btn-verify');
        check.type = 'button';
        const text = make('span', '');
        check.append(icon('check'), text);
        let nameEl: HTMLElement = name;
        const show1 = (on: boolean) => {
          check.classList.toggle('nb-on', on);
          text.textContent = on ? 'Unmark verified' : 'Mark verified';
          check.title = on ? '' : 'Only after comparing this code with the one they see';
          if (!started) detail.textContent = `${on ? 'Verified · ' : ''}${slot === 0 ? 'Created the chat · ' : ''}${as ? `Used the invite made for ${as} · ` : ''}Code ${m.code}`;
        };
        show1(verified);
        check.addEventListener('click', () => {
          const on = !isVerified(slot);
          setVerified(slot, on);
          show1(on);
          const fresh = nameNode(slot, 'nb-member-name', false);
          nameEl.replaceWith(fresh);
          nameEl = fresh;
          announce(on ? `${state.nameOf(slot)} marked verified.` : `${state.nameOf(slot)} unmarked.`);
        });
        actions.append(check);
      }
      if (session.owner !== null && slot !== 0 && !(announced && closed)) {
        const label = started ? 'Finish removing' : m ? 'Remove' : 'Revoke invite';
        const remove = make('button', 'btn nb-btn-secondary nb-btn-remove');
        remove.type = 'button';
        const span = make('span', '', label);
        remove.append(span);
        remove.setAttribute('aria-label', `${m ? 'Remove' : 'Revoke the invite for'} ${state.nameOf(slot)}`);
        let armed = 0;
        let armedAt = 0;
        noRepeat(remove);
        remove.addEventListener('click', async () => {
          // Two steps: first click asks, second removes (not a double-click).
          if (!armed) {
            remove.classList.add('nb-armed');
            span.textContent = 'Sure?';
            armedAt = Date.now();
            armed = window.setTimeout(() => {
              armed = 0;
              remove.classList.remove('nb-armed');
              span.textContent = label;
            }, 4000);
            return;
          }
          if (Date.now() - armedAt < CONFIRM_GAP_MS) return;
          clearTimeout(armed);
          armed = 0;
          remove.classList.remove('nb-armed');
          const done = busy(remove, 'Removing…');
          try {
            // First close their place on the server (they can no longer read
            // anything), then tell everyone, whose apps switch to fresh keys
            // this member never gets. If either step fails, the button stays
            // to finish it.
            removeHere(slot); // our next keys must not reach them, nor an admit
            // Always, even when the server says it is done: its word is
            // not proof, and removing twice does no harm.
            await removeMember(id, session.owner!, slot);
            if (isEnded()) return;
            if (!announced) await control({ t: 'remove', id: newRecordId(sodium), time: Date.now(), slot });
            // Shown as removed once the removal is read back from the room.
            for (let i = 0; i < 2 && !state.removalSeen.has(slot) && !isEnded(); i++) await sync();
            announce(state.removalSeen.has(slot) ? `${state.nameOf(slot)} was removed.` : `${state.nameOf(slot)} is being removed.`);
          } catch (e) {
            error.textContent = roomError(e, 'Could not remove them. Try again.');
            show(error);
          } finally {
            done();
          }
          if (!isEnded()) await render();
        });
        actions.append(remove);
      }
      return li;
    }));
  };
  el('room-members-open').addEventListener('click', async () => {
    list.replaceChildren();
    dialog.showModal();
    await render();
  }, { signal });
  el('room-members-close').addEventListener('click', () => dialog.close(), { signal });
}

function initOwner(sodium: Sodium, id: string, session: Session, owner: string, control: (r: ControlRecord) => Promise<void>, gone: () => void, creatorKey: Uint8Array, isEnded: () => boolean, state: RoomState, signal: AbortSignal,
  revokePlace: (slot: number) => Promise<void>): void {
  // Invites.
  const dialog = el<HTMLDialogElement>('room-invite-dialog');
  const form = el<HTMLFormElement>('room-invite-form');
  const label = el<HTMLInputElement>('room-invite-label');
  const result = el('room-invite-result');
  const linkBox = el('room-invite-link');
  const error = el('room-invite-error');
  // This tab's own choices from when it made the chat: the server relays
  // the signed copy, and could hide it from us.
  const settings = session.settings!;
  const revoke = el<HTMLButtonElement>('room-invite-revoke');
  /** The place of the link shown, so Revoke closes that invite. */
  let shown: number | null = null;
  const reset = () => {
    label.value = '';
    linkBox.textContent = '';
    shown = null;
    show(result, false);
    show(form);
    show(error, false);
  };
  /** Places that count against the member limit: members, and invites that can still be used. */
  const placesTaken = () => {
    const taken = new Set<number>([0]);
    for (const [slot, m] of state.members) if (!m.removed && !state.removed.has(slot)) taken.add(slot);
    // Also places this tab let in, even if the server hides their records.
    for (const k of session.known) if (!state.removed.has(k.slot)) taken.add(k.slot);
    for (const inv of session.invites) {
      if (!state.removed.has(inv.slot) && !session.removedSlots.includes(inv.slot) && Date.now() < inv.exp) taken.add(inv.slot);
    }
    return taken.size;
  };
  const ttlText = (seconds: number) => (seconds >= 3600 ? 'hour' : `${seconds / 60} minutes`);
  // Revoking: the place closes on the server (the link stops working at
  // once), then for everyone, by a signed removal. Two steps, like Remove.
  let armed = 0;
  let armedAt = 0;
  noRepeat(revoke);
  revoke.addEventListener('click', async () => {
    const slot = shown;
    if (slot === null) return;
    if (!armed) {
      revoke.classList.add('nb-armed');
      revoke.textContent = 'Sure? Revoke it';
      armedAt = Date.now();
      armed = window.setTimeout(() => {
        armed = 0;
        revoke.classList.remove('nb-armed');
        revoke.textContent = 'Revoke this invite';
      }, 4000);
      return;
    }
    if (Date.now() - armedAt < CONFIRM_GAP_MS) return;
    clearTimeout(armed);
    armed = 0;
    revoke.classList.remove('nb-armed');
    const done = busy(revoke, 'Revoking…');
    try {
      await revokePlace(slot);
      done();
      revoke.textContent = 'Revoke this invite';
      dialog.close();
      announce('The invite was revoked. Its link no longer works.');
    } catch (e) {
      done();
      revoke.textContent = 'Revoke this invite';
      if (e instanceof ApiError && e.status === 404) return gone();
      error.textContent = roomError(e, 'The invite could not be revoked. Try again, or revoke it in Members.');
      show(error);
    }
  }, { signal });
  el('room-invite-open').addEventListener('click', () => {
    reset();
    dialog.showModal();
    label.focus();
  }, { signal });
  el('room-invite-close').addEventListener('click', () => dialog.close(), { signal });
  dialog.addEventListener('close', reset, { signal });
  el('room-invite-another').addEventListener('click', () => {
    reset();
    label.focus();
  }, { signal });
  bindCopy(el<HTMLButtonElement>('room-invite-copy'), () => linkBox.textContent ?? '', 'Invite link copied', linkBox);
  // An invite whose place the server gave but whose signed record did not
  // get posted. The next Create finishes it, with the same record, instead
  // of taking another place (places are never given out twice).
  let unfinished: { slot: number; token: string; secret: Uint8Array; who: string; record: ControlRecord; at: number; ttl: number } | null = null;
  form.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    if (form.getAttribute('aria-busy') === 'true') return;
    show(error, false);
    const who = cleanName(label.value);
    if (!nameAllowed(who)) {
      error.textContent = NAME_RULE;
      show(error);
      label.focus();
      return;
    }
    // The chat's own limit, checked here too: the server's word is not needed for it.
    if (!unfinished && session.invites.length >= MAX_SLOTS - 1) {
      error.textContent = NO_PLACES;
      show(error);
      return;
    }
    if (!unfinished && placesTaken() >= settings.max) {
      error.textContent = `This chat allows ${settings.max} people, and every place is taken or invited. Revoke an invite, or remove someone, to make room.`;
      show(error);
      return;
    }
    const done = busy(el<HTMLButtonElement>('room-invite-create'), 'Creating…');
    form.setAttribute('aria-busy', 'true');
    try {
      // An unfinished invite near the end of its lifetime is let go.
      if (unfinished && Date.now() - unfinished.at > unfinished.ttl * 1000 * 5 / 6) {
        sodium.memzero(unfinished.secret);
        unfinished = null;
      }
      // This invite's own lifetime, chosen in the invite window: never
      // longer than the chat's signed longest.
      const chosen = Number(el<HTMLSelectElement>('room-invite-ttl').value);
      const ttl = INVITE_TTLS.includes(chosen) && chosen <= settings.ttl ? chosen : settings.ttl;
      if (!unfinished) {
        const invite = await createInvite(id, owner, ttl);
        // Every invite gets a new place. A place we already used (a server
        // handing it out twice, to let someone take it) is refused.
        const slot = invite.slot;
        if (slot < 1 || session.invites.some((i) => i.slot === slot) || session.known.some((k) => k.slot === slot) ||
          session.removedSlots.includes(slot) || state.labels.has(slot) || state.members.has(slot)) {
          throw new Error('reused place');
        }
        // The invite's secret proves a join came from this link. It stays in
        // this tab and in the link, never on the server.
        const secret = sodium.randombytes_buf(32);
        // Never write keys back once the room has ended (its keys deleted).
        if (isEnded()) {
          sodium.memzero(secret);
          return;
        }
        // It stops working when its own lifetime ends, signed here: the
        // server enforces it, and this tab refuses joins that come much later.
        const exp = Date.now() + ttl * 1000;
        session.invites.push({ slot, secret: b64(sodium, secret), exp });
        saveSession(id, session);
        // The label shows later whom each invite was for. It is encrypted.
        const rk = unb64(sodium, session.roster!);
        let boxed: string;
        try { boxed = boxName(sodium, rk, who, id, 'label', slot); }
        catch (e) { sodium.memzero(secret); throw e; }
        finally { sodium.memzero(rk); }
        unfinished = { slot, token: invite.token, secret, who, record: { t: 'invite', id: newRecordId(sodium), time: Date.now(), slot, label: boxed, check: inviteCheck(sodium, secret, id, slot), exp }, at: Date.now(), ttl };
      }
      const u = unfinished;
      await control(u.record);
      unfinished = null;
      if (isEnded()) {
        sodium.memzero(u.secret);
        return;
      }
      const roomKey = unb64(sodium, session.key);
      try { linkBox.textContent = `${window.location.origin}/r/${id}#${encodeInviteFragment(sodium, roomKey, u.token, creatorKey, u.secret, u.slot, session.password !== null)}`; }
      finally {
        sodium.memzero(roomKey);
        sodium.memzero(u.secret);
      }
      el('room-invite-who').textContent = u.who || 'one person';
      el('room-invite-ttl-text').textContent = ttlText(u.ttl);
      show(el('room-invite-password-note'), session.password !== null);
      shown = u.slot;
      show(form, false);
      reveal(result);
      linkBox.focus();
    } catch (e) {
      if (e instanceof ApiError && e.status === 404) return gone();
      error.textContent = e instanceof Error && e.message === 'reused place'
        ? 'The server gave this invite a place that was already used, so no link was made. The server may have been tampered with: be careful with this chat.'
        : unfinished
          ? roomError(e, `The invite${unfinished.who ? ` for ${unfinished.who}` : ''} could not be finished. Press Create invite link to try again; it keeps the same place.`)
          : roomError(e, 'The invite could not be created. Try again.');
      show(error);
    } finally {
      done();
      form.removeAttribute('aria-busy');
    }
  }, { signal });
  // Leaving the room forgets an invite that was never finished.
  signal.addEventListener('abort', () => {
    if (unfinished) sodium.memzero(unfinished.secret);
    unfinished = null;
  });
}
