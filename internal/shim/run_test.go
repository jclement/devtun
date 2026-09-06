package shim

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// Twenty references in a template must cost one exchange, not twenty: each one
// is a potential approval prompt, and a deploy that asks twenty times is a
// deploy nobody runs.
func TestRunResolvesEveryReferenceInOneRoundTrip(t *testing.T) {
	session := opSession(t, func(request opRequest) opResponse {
		secrets := make(map[string]string, len(request.Refs))
		for _, ref := range request.Refs {
			secrets[ref] = "value-of-" + ref
		}
		return opResponse{Secrets: secrets}
	})

	// One reference from the ambient environment, two from an env file, and
	// one of those a duplicate of the first — which must not be asked for
	// twice.
	t.Setenv("DEVTUN_TEST_TOKEN", "op://V/I/token")
	envFile := filepath.Join(t.TempDir(), "app.env")
	contents := "DEVTUN_TEST_DB=op://V/I/database\nDEVTUN_TEST_ALIAS=op://V/I/token\n"
	if err := os.WriteFile(envFile, []byte(contents), 0o600); err != nil {
		t.Fatalf("writing the env file: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := session.client().DispatchOp(t.Context(), []string{
		"run", "--env-file", envFile, "--",
		"sh", "-c", `printf '%s|%s|%s' "$DEVTUN_TEST_TOKEN" "$DEVTUN_TEST_DB" "$DEVTUN_TEST_ALIAS"`,
	}, piped("", &stdout, &stderr))

	if code != 0 {
		t.Fatalf("exit = %d, stderr = %q", code, stderr.String())
	}
	want := "value-of-op://V/I/token|value-of-op://V/I/database|value-of-op://V/I/token"
	if stdout.String() != want {
		t.Errorf("the child saw %q, want %q", stdout.String(), want)
	}

	requests := session.opRequests()
	if len(requests) != 1 {
		t.Fatalf("made %d round trips, want exactly one", len(requests))
	}
	if requests[0].Op != opResolve {
		t.Errorf("request = %+v, want a resolve", requests[0])
	}
	refs := slices.Clone(requests[0].Refs)
	slices.Sort(refs)
	if wantRefs := []string{"op://V/I/database", "op://V/I/token"}; !slices.Equal(refs, wantRefs) {
		t.Errorf("resolved %v, want the two distinct references %v", refs, wantRefs)
	}
}

// --no-masking is accepted and ignored, so a script written for the real `op`
// keeps working. Nothing is asked of the session, because nothing in this
// environment is a secret reference.
func TestRunAcceptsNoMaskingAndPropagatesTheExitCode(t *testing.T) {
	session := opSession(t, func(opRequest) opResponse { return opResponse{} })

	var stdout, stderr bytes.Buffer
	code := session.client().DispatchOp(t.Context(),
		[]string{"run", "--no-masking", "--", "sh", "-c", "exit 7"}, piped("", &stdout, &stderr))

	if code != 7 {
		t.Errorf("exit = %d, want the child's own 7 (stderr = %q)", code, stderr.String())
	}
	if requests := session.opRequests(); len(requests) != 0 {
		t.Errorf("made %d round trips for an environment with no references, want none", len(requests))
	}
}

func TestRunRefusesAnUnknownFlag(t *testing.T) {
	session := opSession(t, func(opRequest) opResponse { return opResponse{} })

	var stdout, stderr bytes.Buffer
	code := session.client().DispatchOp(t.Context(),
		[]string{"run", "--env-file-format", "json", "--", "true"}, piped("", &stdout, &stderr))

	if code == 0 {
		t.Error("an unknown flag must not be ignored")
	}
	if !strings.Contains(stderr.String(), "--env-file-format") {
		t.Errorf("stderr = %q, want it to name the flag it did not understand", stderr.String())
	}
	if requests := session.opRequests(); len(requests) != 0 {
		t.Errorf("asked for %d secrets before refusing the flag, want none", len(requests))
	}
}

func TestParseEnvFile(t *testing.T) {
	contents := `# a comment

export TOKEN=op://Personal/Docker/PAT
QUOTED="hello world"
SINGLE='single'
EMPTY=
SPACED = value
URL=postgres://user:pass@host/db?sslmode=require
`
	path := filepath.Join(t.TempDir(), "app.env")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("writing the env file: %v", err)
	}

	got, err := parseEnvFile(path)
	if err != nil {
		t.Fatalf("parseEnvFile: %v", err)
	}
	want := map[string]string{
		"TOKEN":  "op://Personal/Docker/PAT",
		"QUOTED": "hello world",
		"SINGLE": "single",
		"EMPTY":  "",
		"SPACED": "value",
		"URL":    "postgres://user:pass@host/db?sslmode=require",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseEnvFile() = %#v, want %#v", got, want)
	}
}

func TestParseEnvFileRejectsGarbage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.env")
	if err := os.WriteFile(path, []byte("this is not an assignment\n"), 0o600); err != nil {
		t.Fatalf("writing the env file: %v", err)
	}
	if _, err := parseEnvFile(path); err == nil {
		t.Fatal("a malformed env file should be an error, not a silently empty environment")
	}
}
