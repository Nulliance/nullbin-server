package deploy

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// Every documented installation selects its release through "nullbin
// install", run from a fresh clone of main: it checks that the tag is on
// main, published and signed by the Release workflow before anything from
// the tag runs as root. Checking out "refs/tags/$VERSION" straight from the
// GitHub API's answer trusted any tag anyone could push (audit A1). CI runs
// the command itself (the deploy job); this checks what the guides and
// cloud-init tell people to run.
func TestInstallsCheckTheReleaseFirst(t *testing.T) {
	read := func(name string) string {
		t.Helper()
		b, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		return strings.ReplaceAll(string(b), "\r\n", "\n")
	}
	readme := read("../README.md")
	var server, website int
	for _, block := range regexp.MustCompile("(?ms)^```(?:bash|sh)\\n(.*?)\\n```[ \\t]*$").FindAllStringSubmatch(readme, -1) {
		code := block[1]
		if strings.Contains(code, "refs/tags/") {
			t.Errorf("a README command checks out a tag by name, without the release checks:\n%s", code)
		}
		if !strings.Contains(code, "git clone ") {
			continue
		}
		switch {
		case strings.Contains(code, "sudo ./nullbin install"):
			server++
			clone := strings.Index(code, "git clone https://github.com/Nulliance/nullbin-server.git nullbin")
			enter := strings.Index(code, "cd nullbin/deploy")
			install := strings.Index(code, "sudo ./nullbin install")
			if clone < 0 || enter < clone || install < enter || strings.Contains(code, "--no-checkout") || strings.Contains(code, "checkout --detach") {
				t.Errorf("a server install must clone main, enter deploy/ and run install, and check out nothing itself:\n%s", code)
			}
		case strings.Contains(code, "git checkout --detach"):
			website++
			if !regexp.MustCompile(`(?m)^git checkout --detach [0-9a-f]{40}$`).MatchString(code) || !strings.Contains(code, "git describe --tags --exact-match") {
				t.Errorf("the website build must check out the full commit the server checked, then show its version:\n%s", code)
			}
		}
	}
	if server != 2 || website != 1 {
		t.Fatalf("expected the two server installs and the website build, got %d and %d", server, website)
	}

	cloud := read("cloud-init.yaml")
	if strings.Contains(cloud, "refs/tags/") || strings.Contains(cloud, "releases/latest") {
		t.Fatal("cloud-init must leave choosing and checking the release to nullbin install")
	}
	block := regexp.MustCompile(`(?ms)^  - \|\n    set -eu\n(.*?)(?:\n  [-#]|\z)`).FindAllStringSubmatch(cloud, -1)
	found := false
	for _, b := range block {
		code := b[1]
		clone := strings.Index(code, "git clone https://github.com/Nulliance/nullbin-server.git /opt/nullbin")
		install := strings.Index(code, "/opt/nullbin/deploy/nullbin install")
		start := strings.Index(code, "/opt/nullbin/deploy/nullbin start")
		if clone >= 0 && install > clone && start > install {
			found = true
		}
	}
	if !found {
		t.Fatal("cloud-init must clone, install and start in one set -eu block, so a failed check stops it")
	}

	script := read("nullbin")
	for _, cmd := range []string{"    install)\n", "    update)\n"} {
		at := strings.Index(script, cmd)
		if at < 0 {
			t.Fatalf("nullbin has no %q command", strings.TrimSpace(cmd))
		}
		body := script[at:]
		body = body[:strings.Index(body, "\n      ;;\n")]
		check := strings.Index(body, `check_release "$target"`)
		checkout := strings.Index(body, `checkout --quiet --detach "refs/tags/$target"`)
		if check < 0 || checkout < 0 || check > checkout {
			t.Errorf("nullbin %s must check the release before checking it out", strings.TrimSpace(strings.TrimSuffix(cmd, ")\n")))
		}
	}
	for _, step := range []string{"merge-base --is-ancestor", "release_status", "verify_release_tag"} {
		fn := script[strings.Index(script, "  check_release() {"):]
		fn = fn[:strings.Index(fn, "\n  }\n")]
		if !strings.Contains(fn, step) {
			t.Errorf("check_release lost its %s step", step)
		}
	}
}
