package storage

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Startup takes over its data directory (0700, its own folders), so it
// refuses one that is a link or already holds other things (audit A16).
func TestOpenRefusesDirectoriesItShouldNotTakeOver(t *testing.T) {
	limits := Limits{MaxBytes: 1 << 20, MaxPending: 8}
	busy := t.TempDir()
	if err := os.WriteFile(filepath.Join(busy, "passwd"), []byte("root:x:0:0"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenWithLimits(busy, limits); err == nil || !strings.Contains(err.Error(), "other files") {
		t.Fatalf("a directory of other files: %v", err)
	}
	if _, err := os.Stat(filepath.Join(busy, dirPastes)); !os.IsNotExist(err) {
		t.Fatal("folders were created in a refused directory")
	}

	// Empty, missing, a volume with only lost+found, or one already in use: fine.
	fresh := t.TempDir()
	if err := os.Mkdir(filepath.Join(fresh, "lost+found"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{t.TempDir(), filepath.Join(t.TempDir(), "new"), fresh} {
		s, err := OpenWithLimits(dir, limits)
		if err != nil {
			t.Fatalf("%s: %v", dir, err)
		}
		s.Close()
		// Reopening its own directory, with a stray file in it, still works.
		if err := os.WriteFile(filepath.Join(dir, "notes.txt"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		s, err = OpenWithLimits(dir, limits)
		if err != nil {
			t.Fatalf("reopening %s: %v", dir, err)
		}
		s.Close()
	}

	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(t.TempDir(), link); err != nil {
		t.Skipf("cannot create a symbolic link here: %v", err)
	}
	if _, err := OpenWithLimits(link, limits); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("a symbolic link: %v", err)
	}
}
