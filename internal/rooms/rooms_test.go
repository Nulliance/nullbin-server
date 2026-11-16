package rooms

import (
	"bytes"
	"errors"
	"sync"
	"testing"
	"time"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newStore(t *testing.T) (*Store, *clock) {
	t.Helper()
	s := New(DefaultMaxRooms, DefaultMaxBytes)
	c := &clock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	s.SetClock(c.now)
	return s, c
}

func record(n int, b byte) []byte { return bytes.Repeat([]byte{b}, n) }

func TestInvitesAreSingleUseAndOnlyMembersRead(t *testing.T) {
	s, _ := newStore(t)
	c, err := s.Create(time.Hour, someone)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Post(c.ID, c.MemberToken, record(100, 1)); err != nil {
		t.Fatal(err)
	}
	// Nobody but the owner makes invites.
	for _, wrong := range []string{"", c.MemberToken, newToken()} {
		if _, _, err := s.Invite(c.ID, wrong); !errors.Is(err, ErrNotFound) {
			t.Fatalf("invite with %q: %v", wrong, err)
		}
	}
	inv, n, err := s.Invite(c.ID, c.OwnerToken)
	if err != nil || n != 1 {
		t.Fatalf("invite: %d %v", n, err)
	}
	// An invite token is not a member token.
	if _, _, _, err := s.Read(c.ID, inv, 0); !errors.Is(err, ErrNotFound) {
		t.Fatalf("read with an invite: %v", err)
	}
	m, slot, err := s.Join(c.ID, inv)
	if err != nil || slot != 1 {
		t.Fatalf("join: %d %v", slot, err)
	}
	if _, _, err := s.Join(c.ID, inv); !errors.Is(err, ErrInviteUsed) {
		t.Fatalf("second join: %v", err)
	}
	for _, wrong := range []string{"", newToken(), c.OwnerToken, c.MemberToken + "x"} {
		if _, _, err := s.Join(c.ID, wrong); !errors.Is(err, ErrNotFound) {
			t.Fatalf("join with %q: %v", wrong, err)
		}
	}
	recs, next, exp, err := s.Read(c.ID, m, 0)
	if err != nil || next != 1 || len(recs) != 1 || recs[0].From != 0 || !bytes.Equal(recs[0].Data, record(100, 1)) || exp.IsZero() {
		t.Fatalf("read: %v %d %v", recs, next, err)
	}
	// The server stamps the sender's slot; a member cannot claim another.
	if _, err := s.Post(c.ID, m, record(100, 2)); err != nil {
		t.Fatal(err)
	}
	recs, _, _, _ = s.Read(c.ID, c.MemberToken, 1)
	if len(recs) != 1 || recs[0].From != 1 {
		t.Fatalf("sender stamp: %+v", recs)
	}
	// Reads return copies: changing them changes nothing stored.
	recs[0].Data[0] = 9
	again, _, _, _ := s.Read(c.ID, c.MemberToken, 1)
	if again[0].Data[0] != 2 {
		t.Fatal("stored record changed through a read")
	}
	for _, bad := range []int{-1, 3} {
		if _, _, _, err := s.Read(c.ID, m, bad); !errors.Is(err, ErrInvalid) {
			t.Fatalf("after=%d: %v", bad, err)
		}
	}
	// Wrong tokens and other rooms see nothing.
	other, _ := s.Create(time.Hour, someone)
	for _, try := range [][2]string{{c.ID, ""}, {c.ID, c.OwnerToken}, {c.ID, inv}, {other.ID, m}, {"nothex", m}} {
		if _, _, _, err := s.Read(try[0], try[1], 0); !errors.Is(err, ErrNotFound) {
			t.Fatalf("read %v: %v", try, err)
		}
		if _, err := s.Post(try[0], try[1], record(100, 3)); !errors.Is(err, ErrNotFound) {
			t.Fatalf("post %v: %v", try, err)
		}
	}
}

func TestRemovedMembersLoseAccessAndInvitesStayDead(t *testing.T) {
	s, _ := newStore(t)
	c, _ := s.Create(time.Hour, someone)
	inv1, _, _ := s.Invite(c.ID, c.OwnerToken)
	m1, _, _ := s.Join(c.ID, inv1)
	inv2, n2, _ := s.Invite(c.ID, c.OwnerToken)
	if err := s.Remove(c.ID, c.MemberToken, 1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a member removes: %v", err)
	}
	if err := s.Remove(c.ID, c.OwnerToken, 0); !errors.Is(err, ErrInvalid) {
		t.Fatalf("removing the creator: %v", err)
	}
	for _, n := range []int{-1, MaxSlots} {
		if err := s.Remove(c.ID, c.OwnerToken, n); !errors.Is(err, ErrInvalid) {
			t.Fatalf("remove %d: %v", n, err)
		}
	}
	if err := s.Remove(c.ID, c.OwnerToken, 5); !errors.Is(err, ErrNotFound) {
		t.Fatalf("remove a free slot: %v", err)
	}
	if err := s.Remove(c.ID, c.OwnerToken, 1); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := s.Read(c.ID, m1, 0); !errors.Is(err, ErrNotFound) {
		t.Fatalf("removed member reads: %v", err)
	}
	if _, err := s.Post(c.ID, m1, record(100, 1)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("removed member posts: %v", err)
	}
	if _, _, err := s.Join(c.ID, inv1); !errors.Is(err, ErrInviteUsed) {
		t.Fatalf("removed member rejoins: %v", err)
	}
	// An unused invite can be removed too, and then never works.
	if err := s.Remove(c.ID, c.OwnerToken, n2); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Join(c.ID, inv2); !errors.Is(err, ErrInviteUsed) {
		t.Fatalf("cancelled invite: %v", err)
	}
	st, err := s.Members(c.ID, c.OwnerToken)
	if err != nil || st[0] != StateJoined || st[1] != StateRemoved || st[2] != StateRemoved || len(st) != 3 {
		t.Fatalf("members: %v %v", st, err)
	}
	if _, err := s.Members(c.ID, c.MemberToken); !errors.Is(err, ErrNotFound) {
		t.Fatalf("members for a member: %v", err)
	}
	// Removed slots are not reused.
	_, n3, _ := s.Invite(c.ID, c.OwnerToken)
	if n3 != 3 {
		t.Fatalf("next invite slot %d", n3)
	}
}

func TestLimitsAndExpiry(t *testing.T) {
	s, clk := newStore(t)
	c, _ := s.Create(time.Hour, someone)
	for _, n := range []int{0, MinRecordBytes - 1, MaxRecordBytes + 1} {
		if _, err := s.Post(c.ID, c.MemberToken, record(n, 1)); !errors.Is(err, ErrInvalid) {
			t.Fatalf("record of %d bytes: %v", n, err)
		}
	}
	for i := 1; i < MaxSlots; i++ {
		if _, _, err := s.Invite(c.ID, c.OwnerToken); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := s.Invite(c.ID, c.OwnerToken); !errors.Is(err, ErrRoomFull) {
		t.Fatalf("slot %d: %v", MaxSlots, err)
	}
	for i := 0; i < MaxRecords; i++ {
		if _, err := s.Post(c.ID, c.MemberToken, record(MinRecordBytes, 1)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.Post(c.ID, c.MemberToken, record(MinRecordBytes, 1)); !errors.Is(err, ErrRoomFull) {
		t.Fatalf("record %d: %v", MaxRecords+1, err)
	}
	recs, next, _, _ := s.Read(c.ID, c.MemberToken, 0)
	if len(recs) != MaxReadBatch || next != MaxReadBatch {
		t.Fatalf("batch: %d %d", len(recs), next)
	}
	_, bytesBefore := s.Usage()
	// Expired: gone for every token, and its memory is released.
	clk.t = clk.t.Add(time.Hour)
	if _, _, _, err := s.Read(c.ID, c.MemberToken, 0); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired: %v", err)
	}
	if n, b := s.Usage(); n != 0 || b != 0 || bytesBefore == 0 {
		t.Fatalf("usage after expiry: %d rooms, %d bytes", n, b)
	}
	// Sweep removes rooms nobody touches.
	c2, _ := s.Create(time.Hour, someone)
	clk.t = clk.t.Add(2 * time.Hour)
	if n := s.Sweep(); n != 1 {
		t.Fatalf("swept %d", n)
	}
	if err := s.Destroy(c2.ID, c2.OwnerToken); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete after sweep: %v", err)
	}
}

func TestCapacityAndDelete(t *testing.T) {
	s := New(2, roomOverhead*2+MaxRecordBytes+recordOverhead)
	a, err := s.Create(time.Hour, someone)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := s.Create(time.Hour, someone)
	if _, err := s.Create(time.Hour, someone); !errors.Is(err, ErrCapacity) {
		t.Fatalf("third room: %v", err)
	}
	if _, err := s.Post(a.ID, a.MemberToken, record(MaxRecordBytes, 1)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Post(b.ID, b.MemberToken, record(MinRecordBytes, 1)); !errors.Is(err, ErrCapacity) {
		t.Fatalf("over the memory budget: %v", err)
	}
	if err := s.Destroy(a.ID, "wrong"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a wrong token destroys: %v", err)
	}
	if err := s.Destroy(a.ID, a.OwnerToken); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := s.Read(a.ID, a.MemberToken, 0); !errors.Is(err, ErrNotFound) {
		t.Fatalf("read after delete: %v", err)
	}
	if n, used := s.Usage(); n != 1 || used != roomOverhead {
		t.Fatalf("usage after delete: %d %d", n, used)
	}
	if _, err := s.Create(time.Hour, someone); err != nil {
		t.Fatalf("room after a delete: %v", err)
	}
	if _, err := s.Create(0, someone); !errors.Is(err, ErrInvalid) {
		t.Fatalf("no expiry: %v", err)
	}
}

func TestConcurrentJoinsUseAnInviteOnce(t *testing.T) {
	s, _ := newStore(t)
	c, _ := s.Create(time.Hour, someone)
	inv, _, _ := s.Invite(c.ID, c.OwnerToken)
	var wg sync.WaitGroup
	var mu sync.Mutex
	joined := 0
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, _, err := s.Join(c.ID, inv); err == nil {
				mu.Lock()
				joined++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if joined != 1 {
		t.Fatalf("%d joins with one invite", joined)
	}
}

func TestDeleteZeroesRecords(t *testing.T) {
	s, _ := newStore(t)
	c, _ := s.Create(time.Hour, someone)
	if _, err := s.Post(c.ID, c.MemberToken, record(100, 7)); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	held := s.rooms[c.ID].records[0].Data
	s.mu.Unlock()
	if err := s.Destroy(c.ID, c.OwnerToken); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(held, make([]byte, 100)) {
		t.Fatal("deleted record not zeroed")
	}
}

func TestValidID(t *testing.T) {
	for _, id := range []string{"", "0123456789abcdef0123456789abcde", "0123456789ABCDEF0123456789abcdef", "0123456789abcdef0123456789abcdeg", "../../etc/passwd0123456789abcdef"} {
		if ValidID(id) {
			t.Fatalf("accepted %q", id)
		}
	}
	if !ValidID("0123456789abcdef0123456789abcdef") {
		t.Fatal("rejected a valid ID")
	}
}

var someone = Creator{Client: [16]byte{1}}

func TestPerNetworkLimits(t *testing.T) {
	s, _ := newStore(t)
	a := Creator{Client: [16]byte{2}}
	for range MaxRoomsPerClient {
		if _, err := s.Create(time.Hour, a); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.Create(time.Hour, a); !errors.Is(err, ErrTooMany) {
		t.Fatalf("room %d from one network: %v", MaxRoomsPerClient+1, err)
	}
	if _, err := s.Create(time.Hour, Creator{Client: [16]byte{3}}); err != nil {
		t.Fatalf("another network: %v", err)
	}
	// IPv6 networks in one /48 share four times a network's allowance.
	site := [16]byte{9}
	made := 0
	for i := 0; ; i++ {
		_, err := s.Create(time.Hour, Creator{Client: [16]byte{10, byte(i)}, Site: site, HasSite: true})
		if errors.Is(err, ErrTooMany) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		made++
	}
	if made != MaxRoomsPerClient*siteFactor {
		t.Fatalf("%d rooms from one /48", made)
	}
}

func TestByteLimitsAndReadSize(t *testing.T) {
	s, _ := newStore(t)
	by := Creator{Client: [16]byte{4}}
	c, _ := s.Create(time.Hour, by)
	big := record(MaxRecordBytes, 1)
	n := 0
	for {
		_, err := s.Post(c.ID, c.MemberToken, big)
		if errors.Is(err, ErrRoomFull) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		n++
	}
	if n != MaxRoomBytes/MaxRecordBytes {
		t.Fatalf("%d full records fit one room", n)
	}
	// One read returns at most MaxReadBytes of records.
	recs, next, _, _ := s.Read(c.ID, c.MemberToken, 0)
	if len(recs) != MaxReadBytes/MaxRecordBytes || next != len(recs) {
		t.Fatalf("read %d records", len(recs))
	}
	// A network's rooms together hold at most MaxBytesPerClient.
	total := int64(n * MaxRecordBytes)
	for total < MaxBytesPerClient {
		r, err := s.Create(time.Hour, by)
		if err != nil {
			t.Fatal(err)
		}
		for {
			if _, err := s.Post(r.ID, r.MemberToken, big); err != nil {
				if !errors.Is(err, ErrRoomFull) {
					t.Fatal(err)
				}
				break
			}
			total += MaxRecordBytes
		}
	}
	if total != MaxBytesPerClient {
		t.Fatalf("one network's rooms hold %d bytes", total)
	}
	// Deleting a room gives its bytes back.
	if err := s.Destroy(c.ID, c.OwnerToken); err != nil {
		t.Fatal(err)
	}
	r, _ := s.Create(time.Hour, by)
	if _, err := s.Post(r.ID, r.MemberToken, big); err != nil {
		t.Fatalf("after a delete: %v", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if u := s.clients[by.Client]; u == nil || u.bytes > MaxBytesPerClient {
		t.Fatalf("usage %+v", u)
	}
}

func TestUsageIsForgottenWhenRoomsEnd(t *testing.T) {
	s, clk := newStore(t)
	c, _ := s.Create(time.Hour, Creator{Client: [16]byte{5}, Site: [16]byte{6}, HasSite: true})
	s.Post(c.ID, c.MemberToken, record(100, 1))
	clk.t = clk.t.Add(2 * time.Hour)
	s.Sweep()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.clients) != 0 || len(s.sites) != 0 {
		t.Fatalf("usage kept after rooms ended: %d %d", len(s.clients), len(s.sites))
	}
}

func TestAnyMemberCanSelfDestructButNotOthers(t *testing.T) {
	s, _ := newStore(t)
	c, _ := s.Create(time.Hour, someone)
	inv, _, _ := s.Invite(c.ID, c.OwnerToken)
	m, _, _ := s.Join(c.ID, inv)
	inv2, n2, _ := s.Invite(c.ID, c.OwnerToken)
	other, _ := s.Create(time.Hour, someone)
	// An unused invite, another room's token, or a removed member cannot.
	for _, wrong := range []string{"", inv2, other.MemberToken, other.OwnerToken} {
		if err := s.Destroy(c.ID, wrong); !errors.Is(err, ErrNotFound) {
			t.Fatalf("destroy with %q: %v", wrong, err)
		}
	}
	inv3, n3, _ := s.Invite(c.ID, c.OwnerToken)
	m3, _, _ := s.Join(c.ID, inv3)
	s.Remove(c.ID, c.OwnerToken, n3)
	if err := s.Destroy(c.ID, m3); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a removed member destroys: %v", err)
	}
	_ = n2
	// Only after the owner approves the pending member.
	if _, err := s.Post(c.ID, m, record(100, 1)); err != nil {
		t.Fatal(err)
	}
	if err := s.Admit(c.ID, c.OwnerToken, 1); err != nil {
		t.Fatal(err)
	}
	if err := s.Destroy(c.ID, m); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := s.Read(c.ID, c.MemberToken, 0); !errors.Is(err, ErrNotFound) {
		t.Fatalf("read after self-destruct: %v", err)
	}
}

func TestMalformedTokensMatchNothing(t *testing.T) {
	s, _ := newStore(t)
	c, err := s.Create(time.Hour, someone)
	if err != nil {
		t.Fatal(err)
	}
	inv, _, err := s.Invite(c.ID, c.OwnerToken)
	if err != nil {
		t.Fatal(err)
	}
	// Anything but the 43 base64url characters a token is never matches,
	// not even a stored token with something added or changed.
	for _, bad := range []string{"", c.MemberToken + "A", c.MemberToken[1:], " " + c.MemberToken[1:], c.MemberToken[:42] + "=", c.MemberToken[:42] + "+"} {
		if _, _, _, err := s.Read(c.ID, bad, 0); !errors.Is(err, ErrNotFound) {
			t.Fatalf("read with %q: %v", bad, err)
		}
		if err := s.Destroy(c.ID, bad); !errors.Is(err, ErrNotFound) {
			t.Fatalf("destroy with %q: %v", bad, err)
		}
	}
	for _, bad := range []string{inv + "A", inv[1:]} {
		if _, _, err := s.Join(c.ID, bad); !errors.Is(err, ErrNotFound) {
			t.Fatalf("join with %q: %v", bad, err)
		}
	}
	if _, err := s.Members(c.ID, c.OwnerToken[1:]); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	// A room that does not exist answers the same way.
	other := "0123456789abcdef0123456789abcdef"
	if _, _, _, err := s.Read(other, c.MemberToken, 0); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	if _, _, err := s.Join(other, inv); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
}

func TestInvitesExpireUnused(t *testing.T) {
	s, clk := newStore(t)
	c, err := s.Create(24*time.Hour, someone)
	if err != nil {
		t.Fatal(err)
	}
	old, n, err := s.Invite(c.ID, c.OwnerToken)
	if err != nil {
		t.Fatal(err)
	}
	clk.t = clk.t.Add(InviteTTL - time.Second)
	fresh, _, err := s.Invite(c.ID, c.OwnerToken)
	if err != nil {
		t.Fatal(err)
	}
	clk.t = clk.t.Add(time.Second)
	if _, _, err := s.Join(c.ID, old); !errors.Is(err, ErrInviteExpired) {
		t.Fatalf("an hour-old invite: %v", err)
	}
	st, err := s.Members(c.ID, c.OwnerToken)
	if err != nil || st[n] != StateExpired {
		t.Fatalf("members: %v %v", st, err)
	}
	if _, _, err := s.Join(c.ID, fresh); err != nil {
		t.Fatalf("a newer invite still works: %v", err)
	}
	if err := s.Remove(c.ID, c.OwnerToken, n); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Join(c.ID, old); !errors.Is(err, ErrInviteUsed) {
		t.Fatalf("a cancelled invite: %v", err)
	}
}

func TestMemberLimitCountsMembersAndLiveInvites(t *testing.T) {
	s, clk := newStore(t)
	c, err := s.CreateWith(Options{Expires: 24 * time.Hour, MaxMembers: 3, InviteTTL: 5 * time.Minute}, someone)
	if err != nil {
		t.Fatal(err)
	}
	a, na, err := s.Invite(c.ID, c.OwnerToken)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Invite(c.ID, c.OwnerToken); err != nil {
		t.Fatal(err)
	}
	// The creator and two places: the limit of three is reached, by an
	// unused invite as much as by a member.
	if _, _, err := s.Invite(c.ID, c.OwnerToken); !errors.Is(err, ErrRoomFull) {
		t.Fatalf("a fourth place: %v", err)
	}
	if _, _, err := s.Join(c.ID, a); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Invite(c.ID, c.OwnerToken); !errors.Is(err, ErrRoomFull) {
		t.Fatalf("still full once one joined: %v", err)
	}
	// A removed member frees a place; so does an invite that expired unused.
	if err := s.Remove(c.ID, c.OwnerToken, na); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Invite(c.ID, c.OwnerToken); err != nil {
		t.Fatalf("after a removal: %v", err)
	}
	if _, _, err := s.Invite(c.ID, c.OwnerToken); !errors.Is(err, ErrRoomFull) {
		t.Fatalf("full again: %v", err)
	}
	clk.t = clk.t.Add(5 * time.Minute)
	if _, _, err := s.Invite(c.ID, c.OwnerToken); err != nil {
		t.Fatalf("after invites expired: %v", err)
	}
}

func TestOneToOneRoomTakesOneInvite(t *testing.T) {
	s, _ := newStore(t)
	c, err := s.CreateWith(Options{Expires: time.Hour, MaxMembers: MinMembers, InviteTTL: InviteTTL}, someone)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Invite(c.ID, c.OwnerToken); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Invite(c.ID, c.OwnerToken); !errors.Is(err, ErrRoomFull) {
		t.Fatalf("a second invite in a one-to-one room: %v", err)
	}
}

func TestShortInviteLifetime(t *testing.T) {
	s, clk := newStore(t)
	c, err := s.CreateWith(Options{Expires: time.Hour, MaxMembers: MaxSlots, InviteTTL: 5 * time.Minute}, someone)
	if err != nil {
		t.Fatal(err)
	}
	old, n, _ := s.Invite(c.ID, c.OwnerToken)
	clk.t = clk.t.Add(5*time.Minute - time.Second)
	fresh, _, _ := s.Invite(c.ID, c.OwnerToken)
	clk.t = clk.t.Add(time.Second)
	if _, _, err := s.Join(c.ID, old); !errors.Is(err, ErrInviteExpired) {
		t.Fatalf("a five-minute-old invite: %v", err)
	}
	if st, _ := s.Members(c.ID, c.OwnerToken); st[n] != StateExpired {
		t.Fatalf("members: %v", st)
	}
	if _, _, err := s.Join(c.ID, fresh); err != nil {
		t.Fatal(err)
	}
}

func TestRevokedInviteNeverWorks(t *testing.T) {
	s, _ := newStore(t)
	c, _ := s.Create(time.Hour, someone)
	inv, n, err := s.Invite(c.ID, c.OwnerToken)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Remove(c.ID, c.OwnerToken, n); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Join(c.ID, inv); !errors.Is(err, ErrInviteUsed) {
		t.Fatalf("a revoked invite: %v", err)
	}
	if st, _ := s.Members(c.ID, c.OwnerToken); st[n] != StateRemoved {
		t.Fatalf("members: %v", st)
	}
}

func TestCreateWithRejectsBadOptions(t *testing.T) {
	s, _ := newStore(t)
	for _, o := range []Options{
		{Expires: time.Hour, MaxMembers: 1, InviteTTL: InviteTTL},
		{Expires: time.Hour, MaxMembers: MaxSlots + 1, InviteTTL: InviteTTL},
		{Expires: time.Hour, MaxMembers: MaxSlots, InviteTTL: 0},
		{Expires: time.Hour, MaxMembers: MaxSlots, InviteTTL: InviteTTL + time.Second},
		{Expires: 0, MaxMembers: MaxSlots, InviteTTL: InviteTTL},
	} {
		if _, err := s.CreateWith(o, someone); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%+v: %v", o, err)
		}
	}
}

func TestPlacesAreNeverReused(t *testing.T) {
	s, _ := newStore(t)
	c, _ := s.Create(time.Hour, someone)
	for i := 1; i < MaxSlots; i++ {
		_, n, err := s.Invite(c.ID, c.OwnerToken)
		if err != nil || n != i {
			t.Fatalf("invite %d: %d %v", i, n, err)
		}
		if err := s.Remove(c.ID, c.OwnerToken, n); err != nil {
			t.Fatal(err)
		}
	}
	// Below the member limit, but every place was given out once: removing
	// someone does not free a place, and the error says which case it is.
	if _, _, err := s.Invite(c.ID, c.OwnerToken); !errors.Is(err, ErrNoPlaces) {
		t.Fatalf("a twentieth place: %v", err)
	}
}

func TestEachInviteChoosesItsLifetime(t *testing.T) {
	s, clk := newStore(t)
	c, err := s.CreateWith(Options{Expires: time.Hour, MaxMembers: MaxSlots, InviteTTL: 15 * time.Minute}, someone)
	if err != nil {
		t.Fatal(err)
	}
	short, ns, err := s.InviteFor(c.ID, c.OwnerToken, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	long, _, err := s.InviteFor(c.ID, c.OwnerToken, 0) // the room's longest
	if err != nil {
		t.Fatal(err)
	}
	// Longer than the room allows, or not a lifetime at all.
	for _, bad := range []time.Duration{time.Hour, -time.Second, 2 * time.Hour} {
		if _, _, err := s.InviteFor(c.ID, c.OwnerToken, bad); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%v: %v", bad, err)
		}
	}
	clk.t = clk.t.Add(5 * time.Minute)
	if _, _, err := s.Join(c.ID, short); !errors.Is(err, ErrInviteExpired) {
		t.Fatalf("the five-minute invite: %v", err)
	}
	if st, _ := s.Members(c.ID, c.OwnerToken); st[ns] != StateExpired {
		t.Fatalf("members: %v", st)
	}
	if _, _, err := s.Join(c.ID, long); err != nil {
		t.Fatalf("the fifteen-minute invite: %v", err)
	}
}
