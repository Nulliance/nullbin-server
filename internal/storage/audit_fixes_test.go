package storage

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A paste whose blob is missing or the wrong size can never be served, so
// the sweep removes it instead of letting it hold quota until it expires
// (audit A10). Intact pastes stay.
func TestSweepRemovesPastesWithBrokenBlobs(t *testing.T) {
	s, _, dir := newTestStore(t)
	content := bytes.Repeat([]byte{7}, 4096)
	short := publish(t, s, content, false, time.Hour, 1024)
	missing := publish(t, s, content, false, time.Hour, 1024)
	fine := publish(t, s, content, false, time.Hour, 1024)
	if err := os.Truncate(filepath.Join(dir, dirPastes, short.ID, fileBlob), int64(len(content)-1)); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, dirPastes, missing.ID, fileBlob)); err != nil {
		t.Fatal(err)
	}
	if st := s.Sweep(); st.Unreadable != 2 || st.Expired != 0 || st.Errors != 0 {
		t.Fatalf("sweep: %+v, want the 2 broken pastes removed", st)
	}
	for _, id := range []string{short.ID, missing.ID} {
		if _, err := os.Stat(filepath.Join(dir, dirPastes, id)); !os.IsNotExist(err) {
			t.Fatalf("%s was kept: %v", id, err)
		}
	}
	if got := readAll(t, s, fine.ID); !bytes.Equal(got, content) {
		t.Fatal("an intact paste was changed")
	}
	if st := s.Sweep(); st.Unreadable != 0 || st.Errors != 0 {
		t.Fatalf("second sweep: %+v", st)
	}
}

// Each paste has its own turn for limited opens: holding one does not make
// another paste wait (audit A9, where one lock for all did).
func TestLimitedOpensOfDifferentPastesDoNotWait(t *testing.T) {
	s, _, _ := newTestStore(t)
	unlockA := s.readLock("a")
	got, doneB := make(chan struct{}), make(chan struct{})
	go func() {
		unlock := s.readLock("b")
		close(got)
		unlock()
		close(doneB)
	}()
	select {
	case <-got:
	case <-time.After(2 * time.Second):
		t.Fatal("paste b waited for paste a's turn")
	}
	// The same paste still waits its turn.
	second, doneA := make(chan struct{}), make(chan struct{})
	go func() {
		unlock := s.readLock("a")
		close(second)
		unlock()
		close(doneA)
	}()
	select {
	case <-second:
		t.Fatal("a second turn for paste a did not wait")
	case <-time.After(50 * time.Millisecond):
	}
	unlockA()
	<-doneA
	<-doneB
	s.mu.Lock()
	left := len(s.readLocks)
	s.mu.Unlock()
	if left != 0 {
		t.Fatalf("%d turn entries left after every holder finished", left)
	}
}
