package shim

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInjectWritesAPrivateFileInOneRoundTrip(t *testing.T) {
	session := opSession(t, func(request opRequest) opResponse {
		secrets := make(map[string]string, len(request.Refs))
		for _, ref := range request.Refs {
			secrets[ref] = "hunter2"
		}
		return opResponse{Secrets: secrets}
	})

	dir := t.TempDir()
	in := filepath.Join(dir, "app.conf.tpl")
	out := filepath.Join(dir, "app.conf")
	if err := os.WriteFile(in, []byte("user=admin\npass=op://V/I/password\n"), 0o600); err != nil {
		t.Fatalf("writing the template: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := session.client().DispatchOp(t.Context(),
		[]string{"inject", "-i", in, "-o", out}, piped("", &stdout, &stderr))
	if code != 0 {
		t.Fatalf("exit = %d, stderr = %q", code, stderr.String())
	}

	contents, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("reading the injected file: %v", err)
	}
	if string(contents) != "user=admin\npass=hunter2\n" {
		t.Errorf("injected %q, want the reference replaced", contents)
	}

	// The output of an injection is by construction a file full of secrets.
	info, err := os.Stat(out)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("mode = %o, want 0600", mode)
	}

	requests := session.opRequests()
	if len(requests) != 1 || requests[0].Op != opResolve {
		t.Fatalf("requests = %+v, want a single resolve", requests)
	}
}

// A template three-quarters filled in is a deploy-time failure with no obvious
// cause, so a batch the session could not answer in full must leave no file at
// all.
func TestInjectWritesNothingWhenAReferenceIsMissing(t *testing.T) {
	session := opSession(t, func(request opRequest) opResponse {
		// Only the first of the two references comes back.
		return opResponse{Secrets: map[string]string{request.Refs[0]: "hunter2"}}
	})

	dir := t.TempDir()
	in := filepath.Join(dir, "app.conf.tpl")
	out := filepath.Join(dir, "app.conf")
	template := "a=op://V/I/one\nb=op://V/I/two\n"
	if err := os.WriteFile(in, []byte(template), 0o600); err != nil {
		t.Fatalf("writing the template: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := session.client().DispatchOp(t.Context(),
		[]string{"inject", "-i", in, "-o", out}, piped("", &stdout, &stderr))

	if code == 0 {
		t.Error("a partial batch must not report success")
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Errorf("the output file exists after a failed injection (stat err = %v)", err)
	}
	if !strings.Contains(stderr.String(), "1 of 2") {
		t.Errorf("stderr = %q, want it to say how much of the batch came back", stderr.String())
	}
}

// Silently dropping a flag would produce a file that looks right and is not,
// so an unrecognised one stops the injection before anything is asked for.
func TestInjectRefusesAnUnknownFlag(t *testing.T) {
	session := opSession(t, func(opRequest) opResponse {
		return opResponse{Secrets: map[string]string{"op://V/I/password": "hunter2"}}
	})

	dir := t.TempDir()
	in := filepath.Join(dir, "app.conf.tpl")
	out := filepath.Join(dir, "app.conf")
	if err := os.WriteFile(in, []byte("pass=op://V/I/password\n"), 0o600); err != nil {
		t.Fatalf("writing the template: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := session.client().DispatchOp(t.Context(),
		[]string{"inject", "--in-file", in, "--out-file", out, "--no-newline"},
		piped("", &stdout, &stderr))

	if code == 0 {
		t.Error("an unknown flag must not be ignored")
	}
	if !strings.Contains(stderr.String(), "--no-newline") {
		t.Errorf("stderr = %q, want it to name the flag it did not understand", stderr.String())
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Errorf("the output file exists after a refused injection (stat err = %v)", err)
	}
	if requests := session.opRequests(); len(requests) != 0 {
		t.Errorf("asked for %d secrets before refusing the flag, want none", len(requests))
	}
}

// One reference being a prefix of another is the classic substitution bug: a
// naive replace turns op://V/I/password into <value-of-pass>word.
func TestSubstituteHandlesPrefixCollisions(t *testing.T) {
	template := "a=op://V/I/pass\nb=op://V/I/password\n"
	refs := []string{"op://V/I/pass", "op://V/I/password"}
	secrets := map[string]string{
		"op://V/I/pass":     "SHORT",
		"op://V/I/password": "LONG",
	}
	if got, want := substitute(template, refs, secrets), "a=SHORT\nb=LONG\n"; got != want {
		t.Errorf("substitute() = %q, want %q", got, want)
	}
}
