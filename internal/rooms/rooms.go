// Package rooms keeps Null Chats: short-lived, end-to-end encrypted group
// chats. The server only relays and stores opaque encrypted records; the
// room key never reaches it (it travels in the URL fragment of invites).
//
// Rooms live in memory only; this package never writes them to disk (the
// operating system could still swap memory out). A server
// restart ends every room, and nothing about a room remains afterwards.
//
// A room has up to MaxSlots members, or fewer if its creator set a limit.
// Slot 0 is the creator, who also holds the owner token: it creates
// single-use invites, admits, lists and removes members (and revokes invites
// the same way), and deletes the room. An invite token can join once; joining
// replaces it with a pending token until the owner admits it. Every request
// is checked against hashes of these tokens, in constant time, and anything
// else gets ErrNotFound.
package rooms

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

// Limits. They bound the memory one room, and all rooms together, can use.
const (
	MaxSlots       = 20          // members per room, including the creator
	MaxRecords     = 1000        // encrypted records (messages and notices) per room
	MaxRecordBytes = 16 << 10    // one encrypted record
	MinRecordBytes = 1 + 24 + 16 // version byte, nonce and authentication tag
	MaxReadBatch   = 200         // records returned by one read
	MaxReadBytes   = 64 << 10    // record bytes returned by one read (at least one record); small, as each read is buffered whole
	MaxRoomBytes   = 4 << 20     // record bytes one room may hold
	InviteTTL      = time.Hour   // the longest an invite works; a room may choose less (InviteTTLs)
	MinMembers     = 2           // the smallest member limit: the creator and one other

	// Per client network (keyed hash of an IPv4 address or IPv6 /64), and
	// four times that per IPv6 /48: rooms it created that are still live,
	// and the record bytes those rooms hold. One network cannot fill the
	// server's room budget alone: filling it takes 32 networks (or 8 IPv6
	// /48s), and rooms can last a week. The byte cap is one full room.
	MaxRoomsPerClient = 10
	MaxBytesPerClient = MaxRoomBytes
	siteFactor        = 4

	DefaultMaxRooms = 1000
	DefaultMaxBytes = 128 << 20

	recordOverhead = 64      // memory accounted per record besides its bytes
	roomOverhead   = 4 << 10 // memory accounted per room
)

// Expiries are fixed, from 5 minutes to 1 week (rooms live in memory, so
// never longer).
var Expiries = map[int64]time.Duration{
	300:    5 * time.Minute,
	1800:   30 * time.Minute,
	3600:   time.Hour,
	10800:  3 * time.Hour,
	43200:  12 * time.Hour,
	86400:  24 * time.Hour,
	259200: 3 * 24 * time.Hour,
	604800: 7 * 24 * time.Hour,
}

// InviteTTLs are the invite lifetimes a room may choose, by seconds.
var InviteTTLs = map[int64]time.Duration{
	300:  5 * time.Minute,
	900:  15 * time.Minute,
	3600: InviteTTL,
}

// Options are what the creator chooses for a room.
type Options struct {
	Expires    time.Duration // how long the room lives
	MaxMembers int           // MinMembers to MaxSlots, the creator included
	InviteTTL  time.Duration // the longest an unused invite may work: one of InviteTTLs
}

var (
	// ErrNotFound covers unknown and expired rooms and wrong tokens, so
	// callers cannot tell them apart.
	ErrNotFound = errors.New("not found")
	// ErrInviteUsed means the invite token matched, but it was already
	// used or its slot was removed. Only the invite's holder learns this.
	ErrInviteUsed = errors.New("invite already used or removed")
	// ErrInviteExpired means the invite token matched, but nobody used it
	// within the room's invite lifetime: a link that leaks later lets nobody in.
	ErrInviteExpired = errors.New("invite expired")
	// ErrRoomFull means the room has no free slot (or is at its member
	// limit) or no room for records.
	ErrRoomFull = errors.New("room is full")
	// ErrNoPlaces means the room gave out every place it has, ever: places
	// are never reused, so removing someone does not free one.
	ErrNoPlaces = errors.New("room has used all its places")
	// ErrCapacity means the server's memory for rooms is used up.
	ErrCapacity = errors.New("no capacity for rooms")
	// ErrTooMany means the creator's network already has MaxRoomsPerClient
	// live rooms.
	ErrTooMany = errors.New("too many rooms from this network")
	// ErrInvalid means a request that can never succeed (a bad size, the
	// creator's own slot).
	ErrInvalid = errors.New("invalid request")
	// ErrNotAdmitted means a pending invite holder tried to post more than
	// their one join announcement before the owner approved their place.
	ErrNotAdmitted = errors.New("not admitted")
)

type slotState uint8

const (
	slotFree slotState = iota
	slotInvited
	slotPending
	slotJoined
	slotRemoved
)

type slot struct {
	state   slotState
	invite  [sha256.Size]byte // hash of the invite token (kept after use)
	member  [sha256.Size]byte // hash of the member token, once joined
	invited time.Time         // when the invite was made
	ttl     time.Duration     // how long it works: the creator's choice for this invite
	join    int               // index + 1 of a pending place's immutable announcement (0 before posting)
}

// Record is one stored encrypted record and the slot that posted it.
type Record struct {
	From int
	Data []byte
}

type room struct {
	expires time.Time
	// The creator's choices: at most this many places open at once (the
	// creator's included), and the longest any invite may work (each invite
	// chooses its own, up to that).
	maxMembers int
	inviteTTL  time.Duration
	owner      [sha256.Size]byte
	creator    Creator
	slots      [MaxSlots]slot
	records    []Record
	bytes      int64 // accounted: overhead and records
	data       int64 // record bytes only
}

// Creator identifies the network a room was created from, by the keyed
// hashes the rate limiter uses: never a raw address. Site is the IPv6 /48,
// if any.
type Creator struct {
	Client  [16]byte
	Site    [16]byte
	HasSite bool
}

type usage struct {
	rooms int
	bytes int64
}

// Store holds every room. It is safe for concurrent use.
type Store struct {
	mu       sync.Mutex
	rooms    map[string]*room
	clients  map[[16]byte]*usage // per creator network
	sites    map[[16]byte]*usage // per creator IPv6 /48
	bytes    int64
	maxRooms int
	maxBytes int64
	now      func() time.Time
}

// New returns an empty store with the given limits.
func New(maxRooms int, maxBytes int64) *Store {
	return &Store{rooms: make(map[string]*room), clients: make(map[[16]byte]*usage), sites: make(map[[16]byte]*usage), maxRooms: maxRooms, maxBytes: maxBytes, now: time.Now}
}

// SetClock replaces the time source. Tests use it; call it before sharing.
func (s *Store) SetClock(now func() time.Time) { s.now = now }

// Now is the store's current time.
func (s *Store) Now() time.Time { return s.now() }

// ValidID reports whether id is 32 lowercase hexadecimal characters.
func ValidID(id string) bool {
	if len(id) != 32 {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func newToken() string {
	b := make([]byte, 32)
	rand.Read(b) // never fails; crashes the program if the OS RNG does
	return base64.RawURLEncoding.EncodeToString(b)
}

func hash(token string) [sha256.Size]byte { return sha256.Sum256([]byte(token)) }

// presented is the hash of a token a caller presented, computed once and
// outside the lock. ok is false when the token is not in the format
// newToken makes (43 base64url characters); such a token matches nothing.
type presented struct {
	h  [sha256.Size]byte
	ok bool
}

func present(token string) presented {
	if len(token) != 43 {
		return presented{}
	}
	for i := 0; i < len(token); i++ {
		c := token[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return presented{}
		}
	}
	return presented{h: hash(token), ok: true}
}

// matches compares a presented token's hash with a stored hash in constant
// time. A malformed token never matches.
func (p presented) matches(stored [sha256.Size]byte) bool {
	return subtle.ConstantTimeCompare(stored[:], p.h[:]) == 1 && p.ok
}

// decoy stands in for a room that does not exist, so that looking a token
// up in it does the same comparisons as in a real room: timing does not
// show whether a room exists or how many people joined it.
var decoy room

// Created is what Create returns once: the only time the tokens exist in
// the clear on the server.
type Created struct {
	ID          string
	OwnerToken  string
	MemberToken string // the creator's own, for slot 0
	ExpiresAt   time.Time
}

// usageOf returns the usage entries of a creator, creating them if asked.
func (s *Store) usageOf(c Creator, create bool) (client, site *usage) {
	client = s.clients[c.Client]
	if client == nil && create {
		client = &usage{}
		s.clients[c.Client] = client
	}
	if c.HasSite {
		site = s.sites[c.Site]
		if site == nil && create {
			site = &usage{}
			s.sites[c.Site] = site
		}
	}
	return client, site
}

// charge adds rooms and bytes to a creator's usage, forgetting entries
// that drop to nothing.
func (s *Store) charge(c Creator, rooms int, bytes int64) {
	client, site := s.usageOf(c, true)
	client.rooms += rooms
	client.bytes += bytes
	if client.rooms <= 0 && client.bytes <= 0 {
		delete(s.clients, c.Client)
	}
	if site != nil {
		site.rooms += rooms
		site.bytes += bytes
		if site.rooms <= 0 && site.bytes <= 0 {
			delete(s.sites, c.Site)
		}
	}
}

// Create starts a room with the default limits: MaxSlots members and
// invites that work for InviteTTL.
func (s *Store) Create(expiresIn time.Duration, by Creator) (Created, error) {
	return s.CreateWith(Options{Expires: expiresIn, MaxMembers: MaxSlots, InviteTTL: InviteTTL}, by)
}

// CreateWith starts a room whose creator has already joined as slot 0.
func (s *Store) CreateWith(o Options, by Creator) (Created, error) {
	expiresIn := o.Expires
	if expiresIn <= 0 || o.MaxMembers < MinMembers || o.MaxMembers > MaxSlots || o.InviteTTL <= 0 || o.InviteTTL > InviteTTL {
		return Created{}, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.rooms) >= s.maxRooms || s.bytes+roomOverhead > s.maxBytes {
		return Created{}, ErrCapacity
	}
	if client, site := s.usageOf(by, false); (client != nil && client.rooms >= MaxRoomsPerClient) || (site != nil && site.rooms >= MaxRoomsPerClient*siteFactor) {
		return Created{}, ErrTooMany
	}
	var idb [16]byte
	rand.Read(idb[:])
	c := Created{ID: hex.EncodeToString(idb[:]), OwnerToken: newToken(), MemberToken: newToken()}
	c.ExpiresAt = s.now().Add(expiresIn)
	r := &room{expires: c.ExpiresAt, maxMembers: o.MaxMembers, inviteTTL: o.InviteTTL, owner: hash(c.OwnerToken), creator: by, bytes: roomOverhead}
	r.slots[0] = slot{state: slotJoined, member: hash(c.MemberToken)}
	s.rooms[c.ID] = r
	s.bytes += r.bytes
	s.charge(by, 1, 0)
	return c, nil
}

// live returns the room if it exists and has not expired. An expired room
// is removed on the spot. The caller holds s.mu.
func (s *Store) live(id string) *room {
	if !ValidID(id) {
		return nil
	}
	r := s.rooms[id]
	if r == nil {
		return nil
	}
	if !s.now().Before(r.expires) {
		s.dropLocked(id, r)
		return nil
	}
	return r
}

// dropLocked forgets a room and zeroes what it held.
func (s *Store) dropLocked(id string, r *room) {
	for _, rec := range r.records {
		clear(rec.Data)
	}
	r.records = nil
	s.bytes -= r.bytes
	s.charge(r.creator, -1, -r.data)
	delete(s.rooms, id)
}

// owned returns the room if the presented token is its owner's.
func (s *Store) owned(id string, owner presented) *room {
	r := s.live(id)
	look := r
	if look == nil {
		look = &decoy
	}
	if !owner.matches(look.owner) || r == nil {
		return nil
	}
	return r
}

// member returns the room and the pending or joined slot whose token matches.
// Every slot is compared, whatever its state and whether or not the room
// exists, so timing shows neither which slot matched nor how many joined.
func (s *Store) member(id string, token presented) (*room, int) {
	r := s.live(id)
	look := r
	if look == nil {
		look = &decoy
	}
	found := -1
	for i := range look.slots {
		if token.matches(look.slots[i].member) && (look.slots[i].state == slotPending || look.slots[i].state == slotJoined) && s.open(look, i) && found < 0 {
			found = i
		}
	}
	if r == nil || found < 0 {
		return nil, -1
	}
	return r, found
}

// open reports whether slot i holds a place that counts against the room's
// member limit: an admitted member, or an unexpired invite/pending place.
// Admission must finish within the original invite lifetime.
func (s *Store) open(r *room, i int) bool {
	switch r.slots[i].state {
	case slotJoined:
		return true
	case slotInvited, slotPending:
		return s.now().Before(r.slots[i].invited.Add(r.slots[i].ttl))
	}
	return false
}

// Invite reserves a free slot for one new member and returns its
// single-use invite token, which works for the room's longest invite
// lifetime. A room at its member limit (counting members and invites that
// still work) gets ErrRoomFull.
func (s *Store) Invite(id, ownerToken string) (token string, n int, err error) {
	return s.InviteFor(id, ownerToken, 0)
}

// InviteFor is Invite with the invite's own lifetime: one of InviteTTLs, at
// most the room's longest (0 means that longest).
func (s *Store) InviteFor(id, ownerToken string, ttl time.Duration) (token string, n int, err error) {
	if ttl < 0 || ttl > InviteTTL {
		return "", 0, ErrInvalid
	}
	owner := present(ownerToken)
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.owned(id, owner)
	if r == nil {
		return "", 0, ErrNotFound
	}
	used := 0
	for i := range r.slots {
		if s.open(r, i) {
			used++
		}
	}
	if ttl == 0 {
		ttl = r.inviteTTL
	}
	if ttl > r.inviteTTL {
		return "", 0, ErrInvalid
	}
	if used >= r.maxMembers {
		return "", 0, ErrRoomFull
	}
	for i := 1; i < MaxSlots; i++ {
		if r.slots[i].state == slotFree {
			token = newToken()
			r.slots[i] = slot{state: slotInvited, invite: hash(token), invited: s.now(), ttl: ttl}
			return token, i, nil
		}
	}
	return "", 0, ErrNoPlaces
}

// Join consumes an invite and issues a pending token. Until the owner
// admits the place, it can read ciphertext and post one join announcement,
// but cannot send further records or destroy the room.
func (s *Store) Join(id, inviteToken string) (memberToken string, n int, err error) {
	invite := present(inviteToken)
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.live(id)
	look := r
	if look == nil {
		look = &decoy
	}
	found := -1
	for i := 1; i < MaxSlots; i++ {
		if invite.matches(look.slots[i].invite) && look.slots[i].state != slotFree && found < 0 {
			found = i
		}
	}
	if r == nil || found < 0 {
		return "", 0, ErrNotFound
	}
	if r.slots[found].state != slotInvited {
		return "", 0, ErrInviteUsed
	}
	if !s.now().Before(r.slots[found].invited.Add(r.slots[found].ttl)) {
		return "", 0, ErrInviteExpired
	}
	// Also assert capacity here, including if a test clock moves backwards.
	used := 0
	for i := range r.slots {
		if i != found && s.open(r, i) {
			used++
		}
	}
	if used >= r.maxMembers {
		return "", 0, ErrRoomFull
	}
	memberToken = newToken()
	r.slots[found].state = slotPending
	r.slots[found].member = hash(memberToken)
	return memberToken, found, nil
}

// Admit grants full member permissions after the creator's browser has
// verified the join's invite and password proof. Only the owner may do it.
// Retrying an admission succeeds; a removed place can never be reopened.
func (s *Store) Admit(id, ownerToken string, n int) error {
	owner := present(ownerToken)
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.owned(id, owner)
	if r == nil {
		return ErrNotFound
	}
	if n <= 0 || n >= MaxSlots {
		return ErrInvalid
	}
	sl := &r.slots[n]
	if sl.state == slotJoined {
		return nil
	}
	if sl.state != slotPending || sl.join == 0 || !s.open(r, n) {
		return ErrNotFound
	}
	sl.state = slotJoined
	return nil
}

// Post stores one encrypted record from a member.
func (s *Store) Post(id, memberToken string, data []byte) (int, error) {
	if len(data) < MinRecordBytes || len(data) > MaxRecordBytes {
		return 0, ErrInvalid
	}
	member := present(memberToken)
	s.mu.Lock()
	defer s.mu.Unlock()
	r, from := s.member(id, member)
	if r == nil {
		return 0, ErrNotFound
	}
	sl := &r.slots[from]
	if sl.state == slotPending && sl.join != 0 {
		// A lost reply can be retried without consuming records or memory.
		// Any different record waits for the owner's approval.
		if bytes.Equal(r.records[sl.join-1].Data, data) {
			return sl.join - 1, nil
		}
		return 0, ErrNotAdmitted
	}
	n := int64(len(data))
	if len(r.records) >= MaxRecords || r.data+n > MaxRoomBytes {
		return 0, ErrRoomFull
	}
	if client, site := s.usageOf(r.creator, false); (client != nil && client.bytes+n > MaxBytesPerClient) || (site != nil && site.bytes+n > MaxBytesPerClient*siteFactor) {
		return 0, ErrRoomFull
	}
	cost := n + recordOverhead
	if s.bytes+cost > s.maxBytes {
		return 0, ErrCapacity
	}
	r.records = append(r.records, Record{From: from, Data: append([]byte(nil), data...)})
	if sl.state == slotPending {
		sl.join = len(r.records)
	}
	r.bytes += cost
	r.data += n
	s.bytes += cost
	s.charge(r.creator, 0, n)
	return len(r.records) - 1, nil
}

// Read returns copies of up to MaxReadBatch records after the first
// `after` ones, the index to ask for next, and when the room expires.
func (s *Store) Read(id, memberToken string, after int) ([]Record, int, time.Time, error) {
	member := present(memberToken)
	s.mu.Lock()
	defer s.mu.Unlock()
	r, _ := s.member(id, member)
	if r == nil {
		return nil, 0, time.Time{}, ErrNotFound
	}
	if after < 0 || after > len(r.records) {
		return nil, 0, time.Time{}, ErrInvalid
	}
	end := after
	size := 0
	for end < len(r.records) && end-after < MaxReadBatch && (end == after || size+len(r.records[end].Data) <= MaxReadBytes) {
		size += len(r.records[end].Data)
		end++
	}
	out := make([]Record, 0, end-after)
	for _, rec := range r.records[after:end] {
		out = append(out, Record{From: rec.From, Data: append([]byte(nil), rec.Data...)})
	}
	return out, end, r.expires, nil
}

// MemberState is what the owner sees about one slot.
type MemberState string

const (
	StateInvited MemberState = "invited"
	StatePending MemberState = "pending"
	StateJoined  MemberState = "joined"
	StateRemoved MemberState = "removed"
	StateExpired MemberState = "expired" // invite or pending place not admitted in time
)

// Members returns the state of every used slot, by slot number, to the
// owner. Free slots are omitted.
func (s *Store) Members(id, ownerToken string) (map[int]MemberState, error) {
	owner := present(ownerToken)
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.owned(id, owner)
	if r == nil {
		return nil, ErrNotFound
	}
	out := make(map[int]MemberState)
	for i, sl := range r.slots {
		switch sl.state {
		case slotInvited:
			out[i] = StateInvited
			if !s.now().Before(sl.invited.Add(sl.ttl)) {
				out[i] = StateExpired
			}
		case slotJoined:
			out[i] = StateJoined
		case slotPending:
			out[i] = StatePending
			if !s.open(r, i) {
				out[i] = StateExpired
			}
		case slotRemoved:
			out[i] = StateRemoved
		}
	}
	return out, nil
}

// Remove closes slot n for good: its invite and member token stop working.
// It also revokes an invite nobody used yet. The creator's slot cannot be
// removed.
func (s *Store) Remove(id, ownerToken string, n int) error {
	owner := present(ownerToken)
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.owned(id, owner)
	if r == nil {
		return ErrNotFound
	}
	if n <= 0 || n >= MaxSlots {
		return ErrInvalid
	}
	if r.slots[n].state == slotFree {
		return ErrNotFound
	}
	r.slots[n].state = slotRemoved
	r.slots[n].member = [sha256.Size]byte{}
	return nil
}

// Destroy ends a room at once, for everyone. Any current member may do it
// (a Null Chat self-destructs on anyone's say), with their member token,
// or the creator with the owner token.
func (s *Store) Destroy(id, token string) error {
	t := present(token)
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.owned(id, t)
	if r == nil {
		var n int
		r, n = s.member(id, t)
		if r != nil && r.slots[n].state != slotJoined {
			r = nil
		}
	}
	if r == nil {
		return ErrNotFound
	}
	s.dropLocked(id, r)
	return nil
}

// Sweep removes expired rooms and returns how many it removed.
func (s *Store) Sweep() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	n := 0
	for id, r := range s.rooms {
		if !now.Before(r.expires) {
			s.dropLocked(id, r)
			n++
		}
	}
	return n
}

// Usage reports the number of rooms and the memory accounted to them.
func (s *Store) Usage() (rooms int, bytes int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.rooms), s.bytes
}
