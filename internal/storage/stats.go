package storage

import (
	"errors"
	"io/fs"
	"math"
	"os"
	"path"
	"time"
)

// Stats summarizes a data directory for its operator. It holds only counts
// and sizes: never paste IDs, tokens, times of single pastes or anything
// else that identifies a paste.
type Stats struct {
	Pastes       int   // published pastes that can still be opened
	Burn         int   // of those, burn after reading
	Discussion   int   // of those, with a discussion
	Comments     int   // comments on those pastes
	PasteBytes   int64 // encrypted bytes of those pastes
	CommentBytes int64 // encrypted bytes of those comments
	Pending      int   // unfinished uploads
	Removable    int   // expired, used-up or invalid pastes the sweeper removes
	Newer        int   // pastes written by a newer release, kept but not served
	Entries      int   // everything counted against the paste limit
	Charged      int64 // storage charged against the budget, as the server counts it
	Skipped      int   // links and non-directory entries, never followed
	Errors       int   // entries whose size could not be read; totals are incomplete
}

// ReadStats reads a data directory without changing it, so it can run while
// the server is running. Entries that change or disappear meanwhile are
// skipped; the result is a snapshot, not exact accounting.
func ReadStats(dir string, now time.Time) (Stats, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return Stats{}, err
	}
	defer root.Close()
	// Only the read-only methods of this Store are used.
	s := &Store{root: root, now: func() time.Time { return now }}
	var st Stats

	for _, parent := range []string{dirPending, dirPastes, dirClaimed} {
		if fi, err := root.Lstat(parent); err != nil || !fi.IsDir() {
			return Stats{}, errors.New("not a Nullbin data directory")
		}
		entries, err := fs.ReadDir(root.FS(), parent)
		if err != nil {
			return Stats{}, errors.New("cannot list storage entries")
		}
		for _, entry := range entries {
			name := entry.Name()
			valid := ValidID(name)
			if parent == dirClaimed {
				valid = validClaimName(name)
			}
			dir := path.Join(parent, name)
			fi, err := root.Lstat(dir)
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			if err != nil {
				st.Errors++
				continue
			}
			if !fi.IsDir() {
				st.Skipped++
				continue
			}
			if charge, err := s.entryCharge(parent, dir); err == nil {
				st.Charged = addCapped(st.Charged, charge)
			} else {
				st.Errors++
			}
			st.Entries++
			if !valid {
				continue
			}
			switch parent {
			case dirPending:
				st.Pending++
			case dirPastes:
				s.countPaste(&st, dir, name)
			}
		}
	}
	return st, nil
}

// addCapped adds non-negative sizes without wrapping around: metadata in a
// tampered data directory could claim absurd sizes.
func addCapped(a, b int64) int64 {
	if b < 0 {
		return a
	}
	if b > math.MaxInt64-a {
		return math.MaxInt64
	}
	return a + b
}

func (s *Store) countPaste(st *Stats, dir, id string) {
	m, err := s.readMeta(dir, id)
	switch {
	case errors.Is(err, ErrNewerFormat):
		st.Newer++
		return
	case errors.Is(err, ErrNotFound):
		if _, lerr := s.root.Lstat(dir); errors.Is(lerr, fs.ErrNotExist) {
			return // removed while counting
		}
		st.Removable++ // a paste without metadata can never be served
		return
	case err != nil:
		st.Removable++
		return
	}
	if s.expired(m) || exhausted(m) {
		st.Removable++
		return
	}
	st.Pastes++
	st.PasteBytes = addCapped(st.PasteBytes, m.Size)
	if m.Burn {
		st.Burn++
	}
	if m.CommentTokenHash != "" {
		st.Discussion++
		cdir := path.Join(dir, dirComments)
		if fi, err := s.root.Lstat(cdir); err == nil && fi.IsDir() {
			names, _ := s.commentNames(cdir) // stats are best effort
			for _, name := range names {
				if fi, err := s.root.Lstat(path.Join(cdir, name)); err == nil && fi.Mode().IsRegular() {
					st.Comments++
					st.CommentBytes = addCapped(st.CommentBytes, fi.Size())
				}
			}
		}
	}
}
