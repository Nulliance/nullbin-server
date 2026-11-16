//go:build !api

package server

import (
	"strings"
	"testing"

	"github.com/jacobzymet/nullbin-go/internal/assets"
)

// The embedded page carries the server's policy as a <meta> tag too, so a
// proxy that strips the Content-Security-Policy header leaves it enforced.
// It must be exactly the header's policy without frame-ancestors (which
// browsers ignore in a meta tag), and come before any script or stylesheet.
func TestEmbeddedPageCarriesTheContentSecurityPolicy(t *testing.T) {
	b, err := assets.Load()
	if err != nil {
		t.Fatal(err)
	}
	page := string(b.HTML)
	want := `<meta http-equiv="Content-Security-Policy" content="` + strings.Replace(ContentSecurityPolicy, "frame-ancestors 'none'; ", "", 1) + `">`
	at := strings.Index(page, want)
	if at < 0 || strings.Count(page, `http-equiv="Content-Security-Policy"`) != 1 {
		t.Fatalf("the embedded page must carry the server's policy once, as %s", want)
	}
	if link := strings.Index(page, "<link"); link >= 0 && link < at {
		t.Fatal("the policy must come before any stylesheet")
	}
	if script := strings.Index(page, "<script"); script >= 0 && script < at {
		t.Fatal("the policy must come before any script")
	}
}
