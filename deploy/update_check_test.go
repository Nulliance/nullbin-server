package deploy

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Exercise the actual scripts with a fake HTTP client, without contacting
// GitHub, installing services, or needing root on the test machine.
type updateFixture struct {
	config, cache, response, calls string
	env                            []string
}

func newUpdateFixture(t *testing.T, installed string) updateFixture {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("release notices use Bash on Linux")
	}
	dir := t.TempDir()
	f := updateFixture{
		config: filepath.Join(dir, "config"), cache: filepath.Join(dir, "cache"),
		response: filepath.Join(dir, "response"), calls: filepath.Join(dir, "calls"),
	}
	bin := filepath.Join(dir, "bin")
	for _, path := range []string{bin, f.cache} {
		if err := os.Mkdir(path, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	f.write(t, f.config, "Nulliance/nullbin-server\n"+installed+"\n")
	f.write(t, filepath.Join(bin, "curl"), `#!/bin/sh
printf 'request\n' >> "$NB_TEST_CALLS"
output=
while [ "$#" -gt 0 ]; do
  if [ "$1" = --output ]; then output=$2; shift; fi
  shift
done
[ -n "$output" ] || exit 2
[ -f "$NB_TEST_RESPONSE" ] || exit 22
cat "$NB_TEST_RESPONSE" > "$output"
`)
	if err := os.Chmod(filepath.Join(bin, "curl"), 0o755); err != nil {
		t.Fatal(err)
	}
	f.env = append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"NB_TEST_RESPONSE="+f.response, "NB_TEST_CALLS="+f.calls)
	return f
}

func (f updateFixture) write(t *testing.T, path, value string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
		t.Fatal(err)
	}
}

func (f updateFixture) run(script string) (string, error) {
	cmd := exec.Command("bash", script, f.config, f.cache)
	cmd.Env = f.env
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func TestUpdateNoticeVersions(t *testing.T) {
	for _, tc := range []struct {
		installed, latest string
		wantNotice        bool
	}{
		{"v1.9.9", "v1.10.0", true},
		{"v1.10.0", "v1.10.1", true},
		{"v1.99.99", "v2.0.0", true},
		{"v1.10.0", "v1.10.0", false},
		{"v2.0.0", "v1.10.0", false},
		{"v1.10.0", "v1.9.9", false},
		{"development", "v2.0.0", false},
		{"v999999999999999999999.0.0", "v999999999999999999999.0.1", true},
	} {
		t.Run(tc.installed+"_"+tc.latest, func(t *testing.T) {
			f := newUpdateFixture(t, tc.installed)
			// A compact response is valid too; we use only the stable tag.
			f.write(t, f.response, fmt.Sprintf(`{"name":"Release", "tag_name":"%s"}`, tc.latest))
			if out, err := f.run("check-update"); err != nil {
				t.Fatalf("check: %v\n%s", err, out)
			}
			out, err := f.run("update-notice")
			if err != nil {
				t.Fatalf("notice: %v\n%s", err, out)
			}
			if got := strings.Contains(out, "Nullbin update available:"); got != tc.wantNotice {
				t.Fatalf("want notice %v, got %q", tc.wantNotice, out)
			}
			if tc.wantNotice && (!strings.Contains(out, tc.latest) || !strings.Contains(out, "sudo ./nullbin update")) {
				t.Fatalf("missing version or update command: %q", out)
			}
			calls, err := os.ReadFile(f.calls)
			if err != nil || string(calls) != "request\n" {
				t.Fatalf("login made a network request: %q (%v)", calls, err)
			}
			// A successful start records the installed version. The old
			// cached result must stop notifying immediately, without a fetch.
			f.write(t, f.config, "Nulliance/nullbin-server\n"+tc.latest+"\n")
			if out, err := f.run("update-notice"); err != nil || out != "" {
				t.Fatalf("stale notice after update: %q (%v)", out, err)
			}
			info, err := os.Stat(filepath.Join(f.cache, "latest"))
			if err != nil || info.Mode().Perm() != 0o644 {
				t.Fatalf("cache must be readable at login: %v (%v)", info, err)
			}
		})
	}
}

func TestFailedUpdateChecksKeepLastResult(t *testing.T) {
	f := newUpdateFixture(t, "v1.0.0")
	latest := filepath.Join(f.cache, "latest")
	f.write(t, latest, "v1.1.0\n")
	for _, response := range []string{
		`{"message":"API rate limit exceeded"}`,
		`{"tag_name":"v1.2.0-rc.1"}`,
		`{"tag_name":"v01.2.0"}`,
		`{"tag_name":"v1.2.0$(touch injected)"}`,
		"{\n\"tag_name\":\"v1.2.0\",\n\"tag_name\":\"v1.3.0\"\n}",
		`{"tag_name":"v1.2.0\u001b[2J"}`,
		`not JSON`,
	} {
		f.write(t, f.response, response)
		if out, err := f.run("check-update"); err == nil {
			t.Fatalf("accepted response %q: %s", response, out)
		}
		got, err := os.ReadFile(latest)
		if err != nil || string(got) != "v1.1.0\n" {
			t.Fatalf("bad response replaced cached release: %q (%v)", got, err)
		}
	}
	if err := os.Remove(f.response); err != nil {
		t.Fatal(err)
	}
	if _, err := f.run("check-update"); err == nil {
		t.Fatal("network failure should fail the service check")
	}
	if out, err := f.run("update-notice"); err != nil || !strings.Contains(out, "v1.1.0") {
		t.Fatalf("offline login lost the cached notice: %q (%v)", out, err)
	}
	entries, err := os.ReadDir(f.cache)
	if err != nil || len(entries) != 1 || entries[0].Name() != "latest" {
		t.Fatalf("temporary response files were not cleaned: %v (%v)", entries, err)
	}
}

func TestUpdateNoticeRejectsMissingOrUntrustedData(t *testing.T) {
	f := newUpdateFixture(t, "v1.0.0")
	if out, err := f.run("update-notice"); err != nil || out != "" {
		t.Fatalf("first login without cache: %q (%v)", out, err)
	}
	for _, latest := range []string{"v2.0.0\x1b[2J\n", "v2.0.0$(id)\n", "v2.0.0-rc.1\n", "\n"} {
		f.write(t, filepath.Join(f.cache, "latest"), latest)
		if out, err := f.run("update-notice"); err != nil || out != "" {
			t.Fatalf("untrusted data reached login: %q (%v)", out, err)
		}
	}
	f.write(t, f.config, "../../other/repository\nv1.0.0\n")
	if _, err := f.run("check-update"); err == nil {
		t.Fatal("accepted invalid repository")
	}
	if _, err := os.Stat(f.calls); !os.IsNotExist(err) {
		t.Fatal("invalid repository made a network request")
	}
}
