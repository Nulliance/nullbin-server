package storage

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestReopenSkipsLinksAndRecoveryStillWorks(t *testing.T) {
	s, _, dir := newTestStore(t)
	c := publish(t, s, []byte("genuine"), false, time.Hour, 100)
	s.Close()
	outside := t.TempDir()
	sentinel := filepath.Join(outside, "keep")
	if err := os.WriteFile(sentinel, []byte("outside data"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, parent := range []string{dirPastes, dirPending, dirClaimed} {
		if err := os.Symlink(outside, filepath.Join(dir, parent, "22222222222222222222222222222222")); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
	}
	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if reopened.SkippedEntries() != 3 {
		t.Fatalf("skipped %d entries", reopened.SkippedEntries())
	}
	if err := reopened.Remove(c.ID); err != nil {
		t.Fatalf("operator recovery: %v", err)
	}
	st, err := ReadStats(dir, time.Now())
	if err != nil || st.Skipped != 3 || st.Entries != 0 {
		t.Fatalf("stats: %+v %v", st, err)
	}
	if b, err := os.ReadFile(sentinel); err != nil || string(b) != "outside data" {
		t.Fatal("outside data changed")
	}
}

func TestChunkDurabilityGateDoesNotBlockReceivingBodies(t *testing.T) {
	s, _, _ := newTestStore(t)
	c, err := s.CreatePending(time.Hour, false, 100, "")
	if err != nil {
		t.Fatal(err)
	}
	for range cap(s.chunkCommits) {
		s.chunkCommits <- struct{}{}
	}
	body, writer := io.Pipe()
	done := make(chan error, 1)
	go func() { done <- s.AppendChunk(c.ID, 0, c.UploadToken, body) }()
	received := make(chan error, 1)
	go func() { _, err := io.Copy(writer, bytes.NewReader(make([]byte, 100))); writer.Close(); received <- err }()
	select {
	case err := <-received:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("gate held while waiting for body")
	}
	select {
	case err := <-done:
		t.Fatalf("durability bypassed saturated gate: %v", err)
	default:
	}
	<-s.chunkCommits
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("chunk did not commit after gate opened")
	}
	if got := len(s.chunkCommits); got != cap(s.chunkCommits)-1 {
		t.Fatalf("slot leaked: %d", got)
	}
}
