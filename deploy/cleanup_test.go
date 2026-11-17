package deploy

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCleanupScopesDockerPruningToNullbin(t *testing.T) {
	script, err := os.ReadFile("nullbin")
	if err != nil {
		t.Fatal(err)
	}
	start := strings.Index(string(script), "    cleanup)\n")
	if start < 0 {
		t.Fatal("missing cleanup command")
	}
	body := string(script)[start+len("    cleanup)\n"):]
	end := strings.Index(body, "      ;;")
	if end < 0 {
		t.Fatal("missing cleanup terminator")
	}
	dir := t.TempDir()
	log := filepath.Join(dir, "docker-calls")
	stub := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$CLEANUP_TEST_LOG\"\n"
	if err := os.WriteFile(filepath.Join(dir, "docker"), []byte(stub), 0700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", "-euc", body[:end])
	cmd.Env = append(os.Environ(), "PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"), "CLEANUP_TEST_LOG="+log)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("cleanup: %v\n%s", err, out)
	}
	got, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "image prune -f --filter label=org.opencontainers.image.title=nullbin\n" {
		t.Fatalf("unscoped or unexpected prune: %s", got)
	}
}
