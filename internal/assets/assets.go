// Package assets describes frontend bundles and their hashes.
//
// The optional combined binary embeds internal/assets/dist (built by npm).
// API-only builds use the api tag and contain no frontend files.
package assets

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
)

// Bundle holds the frontend files and their SHA-256 hashes (hex).
type Bundle struct {
	HTML, JS, CSS                   []byte
	HTMLSHA256, JSSHA256, CSSSHA256 string
	Version                         string
}

type manifest struct {
	Version string            `json:"version"`
	Files   map[string]string `json:"files"`
	Sources map[string]string `json:"sources"`
}

var versionPattern = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}$`)

func readManifest(fsys fs.FS) (manifest, error) {
	var m manifest
	b, err := fs.ReadFile(fsys, "build.json")
	if err != nil {
		return m, fmt.Errorf("frontend provenance missing (run `npm run build` before `go build`): %w", err)
	}
	if json.Unmarshal(b, &m) != nil || !versionPattern.MatchString(m.Version) || len(m.Files) != 3 || len(m.Sources) == 0 {
		return m, errors.New("frontend provenance missing or invalid (run `npm run build` before `go build`)")
	}
	return m, nil
}

// VerifySources compares the manifest with the sources compiled into this
// binary, including dirty edits and new files. It needs neither Git nor a
// source checkout at runtime and works with -buildvcs=false and Docker.
func VerifySources(fsys, sources fs.FS) error {
	m, err := readManifest(fsys)
	if err != nil {
		return err
	}
	count := 0
	err = fs.WalkDir(sources, ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		b, err := fs.ReadFile(sources, name)
		if err != nil {
			return err
		}
		if m.Sources[name] != sum(b) {
			return errors.New("stale frontend: build inputs changed (run `npm run build` before `go build`)")
		}
		count++
		return nil
	})
	if err != nil {
		return err
	}
	if count != len(m.Sources) {
		return errors.New("stale frontend: build inputs removed (run `npm run build` before `go build`)")
	}
	return nil
}

// LoadFS reads index.html, app.js and app.css from fsys.
func LoadFS(fsys fs.FS) (*Bundle, error) {
	m, err := readManifest(fsys)
	if err != nil {
		return nil, err
	}
	var files [3][]byte
	for i, name := range []string{"index.html", "app.js", "app.css"} {
		b, err := fs.ReadFile(fsys, name)
		if err != nil || len(b) == 0 {
			return nil, fmt.Errorf("frontend file %s missing from the binary (run `npm run build` before `go build`): %w", name, errors.Join(err, fs.ErrNotExist))
		}
		files[i] = b
		if m.Files[name] != sum(b) {
			return nil, errors.New("frontend hash disagrees with its build manifest (run `npm run build` before `go build`)")
		}
	}
	b := New(files[0], files[1], files[2])
	b.Version = m.Version
	return b, nil
}

// New builds a Bundle from raw file contents.
func New(html, js, css []byte) *Bundle {
	return &Bundle{
		HTML: html, JS: js, CSS: css,
		HTMLSHA256: sum(html), JSSHA256: sum(js), CSSSHA256: sum(css),
	}
}

func sum(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
