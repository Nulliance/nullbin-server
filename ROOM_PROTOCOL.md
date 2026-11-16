# Null Chat protocol

This document specifies how Null Chats work, for anyone reviewing their
security. It describes version 1 of control records and version 2 of
message records, as implemented in `web/src/room-crypto.ts` (formats and
primitives), `web/src/room-state.ts` (which records a tab trusts) and
`web/src/room.ts` (what a tab sends, and when). Where this document and the
code differ, the code is what runs; please report the difference.
[THREAT_MODEL.md](THREAT_MODEL.md) (R25) lists the limits in plain language.

## 1. Goals

A room is a group chat of up to 20 places that deletes itself. The server
stores and relays opaque records and is not trusted. The protocol aims for:

- **G1 Confidentiality.** Only members the creator admitted can read
  messages. Not the server, not anyone holding only the room key (which every
  invite link carries), not a removed member for messages sent after the
  other members learned of the removal.
- **G2 Authenticity.** A message shown as from member X was written by the
  holder of X's signing key, unchanged. Nobody, the server included, can
  make an honest member appear to say, edit, unsend or react to anything.
- **G3 Membership integrity.** Only joins the creator's tab admitted become
  members; nobody can replace a member's keys; the server cannot add a
  member, even with the room key.
- **G4 Forward secrecy.** A key taken from a device later does not decrypt
  earlier messages, apart from a short window (section 9).
- **G5 Fork detection.** If someone (a member, or the server with a
  member's help) shows members different conversations, members are warned,
  and the warning names only someone whose own signed records show it.
- **G6 Name privacy.** Names, invite labels and the room's name are hidden
  from the server and from anyone holding only the room key.

Non-goals: hiding who posts when and how much (the server sees it);
availability (the server can withhold, delay, reorder or delete records, or
the whole room); history for new members or after a reload; protecting a
member whose device or browser is compromised; protecting against whoever
serves the website's code.

## 2. Parties

- **Creator** (place 0): makes the room, holds the owner token, invites,
  admits and removes members. Trusted by members for who is in the room.
- **Members** (places 1 to 19): each holds a member token and their own
  keys. May be malicious: they can post anything signed with their own key.
- **Server**: stores records in order, stamps each with the place whose
  member token posted it, and enforces tokens. Malicious in the model: it
  can drop, delay, reorder, replay and re-stamp records, and may work with a
  malicious member (and so hold the room key).
- **Invite holders**: anyone with an invite link, used or not, holds the
  room key.

## 3. Primitives

All from libsodium 1.0.x (via `libsodium-wrappers-sumo`).

| Name | Function |
|---|---|
| AEAD | `crypto_aead_xchacha20poly1305_ietf`, random 24-byte nonce |
| Sign | Ed25519, `crypto_sign_detached` / `crypto_sign_verify_detached` |
| Seal | `crypto_box_seal` (X25519 + XSalsa20-Poly1305, ephemeral sender key) |
| KDF | `crypto_kdf_derive_from_key(32, 1, context, key)` (BLAKE2b) |
| H(n, msg, key) | `crypto_generichash` (BLAKE2b) of `n` bytes, keyed or not |
| Random | `randombytes_buf` |

Strings below are UTF-8; `<room>` is the room id (32 lowercase hex), numbers
are decimal, `\0` is a zero byte. `b64u` is unpadded base64url.

## 4. Keys and identities

| Key | Made by | Held by | Purpose |
|---|---|---|---|
| Room key `RK` (32 B) | creator | every invite link and member | `CK_ctl = KDF(RK, "nbroomen")` encrypts control records |
| Roster key `RO` (32 B) | creator | creator; admitted members | encrypts names, labels, the room's name |
| Name key pair `NK` (X25519) | creator | public: creator's join; secret: creator | joiners seal their names to it |
| Signing key pair `S_i` (Ed25519) | each member | own tab; public in join | signs every record; its hash is the safety code |
| Receiving keys `B_i,n` (X25519) | each member | own tab; public in join (n = 0) and `box` records | chain keys and the roster key are sealed to them |
| Invite secret `IS_j` (32 B) | creator | creator's tab; invite link for place j | proves a join came from that link |
| Password key `PK` (32 B) | creator, and each joiner, from the chat's password | creator's tab; a joiner only while joining | with IS_j, proves a join knew the password (optional) |
| Chain key `CK` (32 B) | each sender, per generation | sender; members it was delivered to | derives one key per message |
| Tokens | server | as below | owner, invite (single use) and member tokens, 32 random bytes |

An invite link is
`https://<host>/r/<id>#<b64u RK>.i<invite token>.c<b64u S_0 public>.s<b64u IS_j>.n<j>[.p]`.
The fragment never reaches the server. The creator's public signing key in
it is the joiner's trust anchor. `.p` is only a hint that the chat has a
password (the page asks for it at once); the creator's signed `room` record
decides.

The **password key** is `PK = Argon2id(NFC(password), salt =
H(16, "nullbin room password salt v1 <room>"), OPSLIMIT_MODERATE,
MEMLIMIT_MODERATE)`, 32 bytes. The password (1 to 1,024 bytes) never leaves
the browser it is typed in; the creator's tab keeps PK in its session.

The **safety code** of a member is 30 digits from
`H(32, S_public, key = "nullbin room safety code v2")`, read as six 32-bit
big-endian numbers, each mod 100000.

## 5. Wire formats

The server stores each record with the place that posted it (`from`).

**Plaintext layout** (both kinds): `length (4, BE) || JSON || signature (64)
|| zeros`, padded to `paddedLength(4 + length + 64, min)` (the paste
format's padding: `min` for anything smaller, then Padmé), with `min` = 1024
for control records and 2048 for messages. Readers require exactly that
length and all-zero padding.

**Control record** (version 1):

    1 || nonce (24) || AEAD(plain, key = CK_ctl, AD = "nullbin room v1 <room> <from>")

signature = `Sign(S_from, "nullbin room record v1\0<room>\0<from>\0" || JSON)`.

**Message record** (version 2):

    2 || gen (4, BE) || index (4, BE) || nonce (24)
      || AEAD(plain, key = MK, AD = "nullbin room msg v1 <room> <from> <gen> <index>")
      || outer (64)

inner signature = `Sign(S_from, "nullbin room message v1\0<room>\0<from>\0<gen>\0<index>\0" || JSON)`;
outer = `Sign(S_from, "nullbin room message outer v1\0<room>\0<from>\0" || everything before it)`.
Every reader checks the outer signature before decrypting.

**Chains.** A chain is `(gen, index, CK)`; a new generation starts at
index 0 with a random `CK`. For the message at the current index:
`MK = KDF(CK, "nbrmmsgk")`, then `CK ← KDF(CK, "nbrmnext")`, index + 1; each
replaced key is zeroed. gen ≥ 1; gen and index ≤ 2^31 − 1.

**Sealed chain key** (in a `keys` record), for sender place s, at (gen,
index), to member place t, with t's receiving key B:

    Seal(CK || H(16, "nullbin room chain key v2 <room> <s> <gen> <index> to <t>"), B)

The roster key in an `admit` for place t uses the same construction with
s = −1 − t, gen = index = 0, sealed to t's join receiving key (n = 0).

**Chain commitment**: `b64u(H(16, "nullbin room chain commit v1 <room> <s> <gen> <index>", key = CK))`.

**Names** (`boxName`): a name of at most 160 UTF-8 bytes, zero-padded to
160, as `b64u(nonce || AEAD(pad, key = RO, AD = "nullbin room name v1 <room> <kind> <place>"))`,
kind ∈ {member, label, room}.

**Sealed name** (a joiner's): `b64u(Seal(pad || H(16, "nullbin room sealed name v1 <room> <j> <key> <box>"), NK_public))`,
where key and box are the joiner's public keys as in their join.

**Join proof**: `b64u(H(32, "nullbin room join v1 <room> <j> <key> <box>", key = IS_j))`;
in a chat with a password, `b64u(H(32, "nullbin room join v2 <room> <j> <key> <box>", key = IS_j || PK))`.
**Invite check**: `b64u(H(32, "nullbin room invite check v1 <room> <j>", key = IS_j))`.

## 6. Records

Every record's JSON has exactly the listed keys (no others), an `id` of 32
lowercase hex characters (random) and a `time` (the sender's clock, ms).
Records are deduplicated by `from` and `id` (joins also by key).

### Control records

| `t` | Fields | Who may post | Accepted when |
|---|---|---|---|
| `join` | `key`, `box`, `name`; creator: `namekey`; others: `proof` | the joiner, at their place | signed by `key`; `box` (and `namekey`) not low-order; place 0 carries `namekey`, others do not; place not removed, no member there yet. Place 0: accepted, and must match a pinned creator key (else *conflict*). Others: a member at once if the creator already admitted that `key` (else rejected); otherwise kept waiting for an admit |
| `room` | `name` (boxed), `ends`, `pw` (boolean), `max` (2 to 20), `ttl` (300, 900 or 3600: the longest any invite may work) | creator | first one only |
| `invite` | `slot`, `label` (boxed), `check`, `exp` (ms) | creator | first per place |
| `admit` | `slot`, `key`, `roster`, `name` (boxed) | creator | first per place; a second with another `key` raises *conflict*; ignored for removed places; refused (*over limit*) if the places admitted and not removed, the creator's included, already reach `max` |
| `remove` | `slot` (not 0) | creator | always (permanent) |
| `keys` | `gen`, `index`, `commit`, `to: [{slot, n, box}]` | any member | see section 7.4 |
| `box` | `n` (1 to 4096), `box` | any member | `n` = current + 1 to current + 64; same `n` with another key is *equivocation* |

Every control record except a join must be signed by the current signing
key of its `from` place, and that place must be a member that is not
removed. `room`, `invite`, `remove` and `admit` must come from place 0.

### Message records

| `t` | Fields | Meaning |
|---|---|---|
| `msg` | `text`, `reply` (`{id, author}` or null), `seen` (20 receipts) | a message |
| `edit` | `target`, `text` | replace the text of the sender's own message `target` |
| `unsend` | `target` | delete the sender's own message `target` |
| `react` | `target`, `author`, `emoji` (one of six), `on` | add or remove a reaction |

Edits and unsends look up `<from>:<target>`, so they only reach the sender's
own messages; reactions and replies name the target's author and id. A
reply whose target the reader does not have is shown without any author.
Text must pass strict rules (no control, format, direction-changing or
default-ignorable characters, joiners only where they do a visible job,
at most 2,000 UTF-16 units, something visible).

A **receipt** is `{slot, gen, index, h}`: for each of the 20 places, the
newest place the sender read there and `h = b64u(H(16, JSON of that record))`,
or `gen = 0` and a fixed `h` for nothing read. Every message carries all 20,
so its size does not depend on what was read.

## 7. Flows

### 7.1 Creating a room

1. The creator's tab asks the server for a room (`POST /api/v1/rooms`, with
   its member limit and the longest invite lifetime) and gets its id, the owner token
   and the creator's member token (place 0).
2. It generates RK, RO, NK, S_0 and B_0,0, and, if the chat has a
   password, derives PK.
3. It posts its `join` (with `namekey` = NK public, its name boxed under
   RO) and a `room` record (name boxed, `ends`, `pw`, `max`, `ttl`).

### 7.2 Inviting

1. The creator's tab refuses if the members and still-usable invites
   already reach `max`. It asks for an invite (`POST /{id}/invites`): the
   server, which counts the same way, returns a single-use invite token and
   a fresh place j (never reused). The creator chooses this invite's
   lifetime (300, 900 or 3600 seconds, at most the room's `ttl`), and the
   server stops the token after it.
2. It generates IS_j, stores it in its session with `exp` = now + that
   lifetime,
   and posts an `invite` record for place j: label boxed under RO, `check`
   (section 5) and `exp`. If posting fails, the next attempt resends the
   same record for the same place.
3. It shows the link (section 4). The server refuses the invite after
   its lifetime. **Revoking** an unused invite is a removal (7.7) of its
   place.

### 7.3 Joining and admitting

1. The joiner opens the link. The fragment is read once and removed from
   the address bar.
2. The joiner uses the invite token (`POST /{id}/join`) and gets a member
   token and its place, which must equal j (else it stops).
3. It fetches the first records and checks that RK opens the creator's
   join, signed by the key in the link, with a name key. Until that check
   passes nothing is saved; if the room cannot be reached, it can retry.
4. If the creator's signed `room` record (in the first records) has `pw`,
   it asks for the password and derives PK. It generates S_j and B_j,0,
   seals its name to NK (bound to its place and keys), computes the join
   proof with IS_j (and PK), stores the invite check, and posts its `join`.
   The joiner cannot check the password first: a wrong one uses up the
   invite.
5. The creator's tab, for each invited place without an admit, checks the
   proof of each waiting join with IS_j. It admits the first valid one
   whose sealed name opens: it records the admitted key in its session
   before posting, then posts an `admit` with the joiner's signing key, RO
   sealed to B_j,0 and the name boxed under RO. It admits each place once,
   ever.
6. If two different valid joins exist for a place (before or after the
   admit), the link leaked: the creator's tab admits neither, removes the
   place and says so. A join whose proof fails is reported to the creator;
   in a chat with a password, its place is removed at once (one guess per
   invite). A valid join first seen more than 10 minutes after the
   invite's `exp`, or when admitting would pass `max`, is not admitted and
   its place is removed.
7. The joiner, on reading the admit for its place, opens RO and becomes a
   member. If the creator's signed `invite` for its place carries a `check`
   that does not match its link's secret, it reports a damaged link and
   leaves. If the admit names another key, it reports that someone took its
   place.

### 7.4 Sending keys

Each sender keeps one chain. Before sending a message, it makes sure every
current member (admitted, not removed, not itself) holds it:

- It starts a new generation (gen + 1, random CK) when it has none, after
  a removal, and after 50 messages on the chain.
- It posts a `keys` record at its current (gen, index): the commitment, and
  for each member not yet holding this chain, CK sealed to that member's
  current receiving key with its number n.

A reader of a `keys` record from sender s:

1. Notes (gen, index) as a place of s; a place before one already seen
   from s marks s *out of order*.
2. If an earlier record committed to a different value for the same
   (s, gen, index), marks s *keys* (two chains for one place).
3. If it holds s's chain at this gen and at or before this index, steps a
   copy forward and checks the commitment; a mismatch, or a step of more
   than 200, marks s *keys*.
4. Finds its own entry. If there is none, or it does not open (unknown
   receiving key, failed seal, or a commitment mismatch, which also marks
   s *keys*), and it does not already hold a chain of this generation,
   counts s as *leaving it out*.
5. If the entry is sealed to one of its own receiving keys that it had
   replaced more than 10 minutes before the record's time, marks s *stale*.
6. Otherwise it replaces s's chain with this one, unless that would move
   the chain back (older gen, or same gen at or before the current index).

### 7.5 Receiving keys

A member announces a new receiving key (`box`, n + 1) at most every three
minutes, after a delivery opened with its current one, or when messages it
cannot read keep arriving (the server may be hiding deliveries sealed to
it). It keeps the old secret for two more minutes, then deletes it (at
most 8 kept).

### 7.6 Messages

A reader of a message from s: checks the outer signature with S_s; notes
its (gen, index) as a place of s (even if unreadable); then, holding s's
chain at that gen, steps a copy to index (at most 200 ahead), derives MK,
decrypts, checks the layout, schema and inner signature, and only then
commits the chain to index + 1. A message behind the chain, from another
generation, too far ahead or not authentic leaves the chain unchanged.

A tab's own messages come back unreadable to it (it deleted their keys);
it shows them as it sends them, and a record signed with its own key that
it never posted marks a *copy* of its keys.

### 7.7 Removal

The creator's tab stops sharing keys with and admitting the place at once,
asks the server to close it (its member token stops working), then posts
`remove`. Every member's tab, on reading it, forgets the removed member's
chain and starts a new generation before its next message, without them.

### 7.8 Leaving, expiry and self-destruct

The session (keys, tokens, chain) lives in the tab's `sessionStorage`.
Leaving the page clears the conversation and keys from the page; coming
back reloads it, which rejoins from the session (new messages only). A web
lock lets one tab at a time use a session; a duplicate deletes its copy.
Any member, or the owner, can delete the room on the server; it also ends
at `ends`, or when the server restarts.

## 8. Warnings and alarms

| Signal | Raised when | Names |
|---|---|---|
| conflict (ends the room in the tab) | the creator's place gets another key than the pinned one; a place gets a second admit with another key | nobody |
| impostor (ends) | the admitted key for our place is not ours | nobody |
| copy (ends) | a record signed with our key that this tab never posted | nobody |
| keys | two receiving keys under one number; two commitments for one place; a delivery that does not step from a chain we hold, or is far ahead | the sender |
| out of order | a sender's signed places step back, or a receiving-key number jumps by more than 64 | the sender, saying the server may be the cause |
| left out | for two minutes, deliveries from s go to others but none we can open | the sender, or the server |
| stale key | a delivery sealed to a key we replaced long before | the sender, or the server |
| receipts | a member's receipts disagree with what we read at that place | the member whose receipts disagree |
| damaged invite / contested / bad proof / late / full | section 7.3 | the place |
| over limit | an admit that would pass the signed `max` (not let in) | nobody |

Nothing a member signs can raise conflict, impostor or copy for everyone;
only the creator's key, or a copy of a member's own keys, can.

## 9. Security argument (informal)

- **G1.** Messages are encrypted under keys derived from CK, which travels
  only sealed to receiving keys of members the creator admitted. RK opens
  control records, not chains. A removed member's chain deliveries stop once
  senders read the removal; messages sent before that may use chains they
  hold.
- **G2.** Every record is signed with the sender's key, which was fixed by
  their own signed join and, for non-creators, the creator's signed admit.
  Signatures bind room, place and (for messages) position. Edits and
  unsends can only target the signer's own messages.
- **G3.** Admission needs the creator's signature. The creator admits only
  joins that prove knowledge of IS_j, which never reaches the server. Tabs
  remember admitted keys and refuse others.
- **G4.** Message keys are deleted after use; receiving keys rotate after
  deliveries and are deleted two minutes later. A stolen device exposes the
  chains it holds (from then on) and deliveries sealed to receiving keys
  not yet deleted.
- **G5.** Commitments, forward-only places and receipts catch members shown
  different chains or messages, once the evidence reaches them.
- **G6.** Names are encrypted under RO, which travels only sealed to admitted
  members; joiners' names travel sealed to the creator.

## 10. Formal model

`proverif/` holds a model of the protocol's core for
[ProVerif](https://bblanche.gitlabpages.inria.fr/proverif/) 2.05, which
looks for attacks on an unbounded number of sessions. The attacker runs the
server (it sees, drops, replays and reorders every record and stamps any
place as sender) and always holds the room key. Three scenarios:

- `outsider.pv`: the attacker holds only the room key (an unused invite).
- `member.pv`: the attacker also holds an invite, so it is an admitted
  member that receives chains like anyone else.
- `password.pv`: the chat has a password (v2 join proofs); the attacker
  holds Alice's invite link, leaked before she used it, but not the
  password.

Run them with:

```bash
proverif -lib proverif/room proverif/outsider.pv
proverif -lib proverif/room proverif/member.pv
proverif -lib proverif/room proverif/password.pv
```

(Without a local install: build an image from `ocaml/opam` with
`opam install proverif.2.05`, and run it with the repository mounted.)

| Property | outsider | member | password |
|---|---|---|---|
| G3: only the honest joiners' keys are admitted for their places | holds | holds | holds, although the attacker has Alice's link |
| G3: a tab takes no other keys as an honest member's | (implied) | holds | holds |
| G2: a message read as X's was sent by X, to that reader | holds | holds | holds |
| G1: a message between two honest members stays secret | holds | holds (from non-members: the attacker member is left out of that chain here, while in the code every member gets every chain) | holds |
| G4: it stays secret after the reader's device is taken later | holds | holds | holds |
| G6: the roster key (all names) stays secret | holds | (the attacker is a member) | holds |
| The password stays secret | | | holds |
| The password resists offline guessing (`weaksecret`) | | | no, as R25 says: a used link and the join made with it let anyone guess offline, one Argon2id per guess |

Each file also asks whether the honest run happens (Bob reads Alice's
message, members are admitted); ProVerif must find that it does ("false",
with a trace), or the other results would be empty. To check that the
model can see attacks at all, each of these changes to it, made one at a
time, makes ProVerif report one: admitting without checking the invite
proof, accepting admits not signed by the creator, sealing to a receiving
key from an unsigned join, keeping an old receiving key, accepting
messages not signed by their sender (which only a model where chains are
shared, as here, can catch), and, in `password.pv`, a creator that checks
proofs without the password key or accepts a v1 proof in a chat with a
password (the link holder is then admitted).

What the model leaves out: the member limit and invite lifetimes (enforced
by the server and by the tabs' bookkeeping, which the unit and browser
tests cover); each chain goes to two members and carries one message
(stepping it is modelled only for forward secrecy); the creator does not
send; removal, receiving-key numbers, padding, schemas, record ids and the
warnings of section 8 are not modelled (the unit tests and the room
fuzzer, `web/test/room-fuzz.test.ts`, cover those). Primitives are ideal,
Argon2id included: a proof about the model is not a proof about the code.

## 11. Known limits

See THREAT_MODEL.md, R25, which includes: the server sees metadata and can
withhold or delay anything; a malicious server can show a late joiner an
old receiving key of someone (whose old secret, if stolen, then reads what
the joiner sends); a link that leaks before its invitee uses it lets its
holder take the place; a malicious member can fill the room or end it;
receipts are each member's own word; lookalike names are folded from a
short list, so comparing safety codes is the real check.

## 12. Constants

| Constant | Value |
|---|---|
| Places | 20 (0 is the creator) |
| Records per room / bytes per record | 1,000 / 16 KiB |
| New chain | after 50 messages, and after a removal |
| Skip ahead in one chain | at most 200 messages |
| Receiving-key numbers | 1 to 4,096, at most 64 ahead |
| Receiving-key rotation / grace | 3 minutes / 2 minutes |
| Left-out warning | after 2 minutes |
| Stale-key and end-time slack | 10 minutes |
| Invite lifetime | chosen per invite: 5 minutes, 15 minutes or 1 hour (its expiry signed); joins seen 10 minutes late are refused |
| Member limit | 2 to 20 (signed), the creator included |
| Password | 1 to 1,024 bytes; Argon2id, moderate limits |
| Names, labels | 40 characters (160 bytes padded) |
| Message text | 2,000 UTF-16 units |
