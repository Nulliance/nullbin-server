package rooms

import (
	"errors"
	"sync"
	"testing"
	"time"
)

func TestPendingPlaceCannotDestroyOrFillRoom(t *testing.T) {
	s, _ := newStore(t)
	c, _ := s.Create(time.Hour, someone)
	invite, n, _ := s.Invite(c.ID, c.OwnerToken)
	member, _, _ := s.Join(c.ID, invite)
	states, _ := s.Members(c.ID, c.OwnerToken)
	if states[n] != StatePending {
		t.Fatalf("before approval: %v", states)
	}
	if err := s.Destroy(c.ID, member); !errors.Is(err, ErrNotFound) {
		t.Fatalf("pending member self-destructed: %v", err)
	}
	if _, _, _, err := s.Read(c.ID, member, 0); err != nil {
		t.Fatalf("pending member needs ciphertext to check its invite: %v", err)
	}
	if err := s.Admit(c.ID, c.OwnerToken, n); !errors.Is(err, ErrNotFound) {
		t.Fatalf("approved without an announcement: %v", err)
	}
	first := record(100, 1)
	index, err := s.Post(c.ID, member, first)
	if err != nil {
		t.Fatal(err)
	}
	_, before := s.Usage()
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Go(func() {
			if got, err := s.Post(c.ID, member, first); err != nil || got != index {
				t.Errorf("retry: index %d, %v", got, err)
			}
			if _, err := s.Post(c.ID, member, record(100, 2)); !errors.Is(err, ErrNotAdmitted) {
				t.Errorf("pending member posted another record: %v", err)
			}
		})
	}
	wg.Wait()
	_, after := s.Usage()
	recs, next, _, err := s.Read(c.ID, c.MemberToken, 0)
	if err != nil || len(recs) != 1 || next != 1 || before != after {
		t.Fatalf("pending retries grew the room: records=%d next=%d bytes=%d/%d err=%v", len(recs), next, before, after, err)
	}
	other, _ := s.Create(time.Hour, someone)
	for _, wrong := range []string{"", member, invite, c.MemberToken, other.OwnerToken} {
		if err := s.Admit(c.ID, wrong, n); !errors.Is(err, ErrNotFound) {
			t.Fatalf("non-owner approved a pending member: %v", err)
		}
	}
	if err := s.Admit(other.ID, c.OwnerToken, n); !errors.Is(err, ErrNotFound) {
		t.Fatalf("approval crossed rooms: %v", err)
	}
	for _, bad := range []int{-1, 0, MaxSlots} {
		if err := s.Admit(c.ID, c.OwnerToken, bad); !errors.Is(err, ErrInvalid) {
			t.Fatalf("approved invalid slot %d: %v", bad, err)
		}
	}
	for i := 0; i < 2; i++ {
		if err := s.Admit(c.ID, c.OwnerToken, n); err != nil {
			t.Fatalf("owner approval/retry: %v", err)
		}
	}
	states, _ = s.Members(c.ID, c.OwnerToken)
	if states[n] != StateJoined {
		t.Fatalf("after approval: %v", states)
	}
	if _, err := s.Post(c.ID, member, record(100, 2)); err != nil {
		t.Fatalf("approved member could not post: %v", err)
	}
	if err := s.Destroy(c.ID, member); err != nil {
		t.Fatalf("approved member could not self-destruct: %v", err)
	}
}

func TestAdmissionCannotReopenRemovedOrUnusedPlaces(t *testing.T) {
	s, _ := newStore(t)
	c, _ := s.Create(time.Hour, someone)
	invite, n, _ := s.Invite(c.ID, c.OwnerToken)
	if err := s.Admit(c.ID, c.OwnerToken, n); !errors.Is(err, ErrNotFound) {
		t.Fatalf("approved unused invite: %v", err)
	}
	member, _, _ := s.Join(c.ID, invite)
	s.Post(c.ID, member, record(100, 1))
	s.Remove(c.ID, c.OwnerToken, n)
	if err := s.Admit(c.ID, c.OwnerToken, n); !errors.Is(err, ErrNotFound) {
		t.Fatalf("reopened removed place: %v", err)
	}
	if _, _, _, err := s.Read(c.ID, member, 0); !errors.Is(err, ErrNotFound) {
		t.Fatalf("removed pending token reads: %v", err)
	}
}
