package release

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// tarGz builds a release archive containing one file.
func tarGz(t *testing.T, name string, body []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatal(err)
	}
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

// serveRelease stands in for GitHub, publishing one archive and its checksums.
func serveRelease(t *testing.T, assets map[string][]byte, corrupt bool) *httptest.Server {
	t.Helper()
	var sums strings.Builder
	for name, body := range assets {
		sum := sha256.Sum256(body)
		digest := hex.EncodeToString(sum[:])
		if corrupt {
			digest = strings.Repeat("0", 64)
		}
		fmt.Fprintf(&sums, "%s  %s\n", digest, name)
	}
	all := map[string][]byte{"checksums.txt": []byte(sums.String())}
	for k, v := range assets {
		all[k] = v
	}

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := filepath.Base(r.URL.Path)
		body, ok := all[name]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(body)
	}))
}

func TestBinaryDownloadsAndVerifies(t *testing.T) {
	want := []byte("#!/bin/sh\necho helper\n")
	asset := "devtun_0.1.0_linux_arm64.tar.gz"
	server := serveRelease(t, map[string][]byte{asset: tarGz(t, "devtun", want)}, false)
	defer server.Close()

	f := &Fetcher{Slug: "jclement/devtun", Version: "v0.1.0", CacheDir: t.TempDir(), BaseURL: server.URL}

	path, err := f.Binary(context.Background(), "linux", "arm64")
	if err != nil {
		t.Fatalf("Binary: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("extracted %q, want %q", got, want)
	}
	// It has to be executable, or uploading it is pointless.
	info, _ := os.Stat(path)
	if info.Mode().Perm()&0o100 == 0 {
		t.Errorf("the helper is not executable: %v", info.Mode())
	}
}

// A checksum that does not match is either a corrupted download or something
// worse, and the difference is not knowable from here.
func TestABadChecksumIsRefused(t *testing.T) {
	asset := "devtun_0.1.0_linux_arm64.tar.gz"
	server := serveRelease(t, map[string][]byte{asset: tarGz(t, "devtun", []byte("x"))}, true)
	defer server.Close()

	f := &Fetcher{Slug: "jclement/devtun", Version: "v0.1.0", CacheDir: t.TempDir(), BaseURL: server.URL}

	_, err := f.Binary(context.Background(), "linux", "arm64")
	if err == nil {
		t.Fatal("a mismatched checksum must not be installed")
	}
	if !strings.Contains(err.Error(), "checksum") {
		t.Errorf("the refusal should say why, got %v", err)
	}
}

// The second call must not download again — a reconnect should not re-fetch a
// helper it already has.
func TestASecondCallUsesTheCache(t *testing.T) {
	asset := "devtun_0.1.0_linux_arm64.tar.gz"
	var hits int
	inner := serveRelease(t, map[string][]byte{asset: tarGz(t, "devtun", []byte("helper"))}, false)
	defer inner.Close()
	counting := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		http.Redirect(w, r, inner.URL+r.URL.Path, http.StatusFound)
	}))
	defer counting.Close()

	f := &Fetcher{Slug: "jclement/devtun", Version: "v0.1.0", CacheDir: t.TempDir(), BaseURL: counting.URL}

	if _, err := f.Binary(context.Background(), "linux", "arm64"); err != nil {
		t.Fatal(err)
	}
	first := hits
	if _, err := f.Binary(context.Background(), "linux", "arm64"); err != nil {
		t.Fatal(err)
	}
	if hits != first {
		t.Errorf("the second call made %d more requests; it should have used the cache", hits-first)
	}
}

// A build with no release cannot download, and should say so distinctly so the
// caller can give a developer the developer message.
func TestADevBuildHasNoReleaseToFetchFrom(t *testing.T) {
	for _, version := range []string{"", "dev"} {
		f := &Fetcher{Slug: "jclement/devtun", Version: version, CacheDir: t.TempDir()}
		if _, err := f.Binary(context.Background(), "linux", "arm64"); !errors.Is(err, ErrNoRelease) {
			t.Errorf("version %q: want ErrNoRelease, got %v", version, err)
		}
	}
}

// A platform the release does not publish should say that, rather than failing
// on a 404 the user has to interpret.
func TestAnUnpublishedPlatformSaysSo(t *testing.T) {
	server := serveRelease(t, map[string][]byte{"devtun_0.1.0_linux_arm64.tar.gz": tarGz(t, "devtun", []byte("x"))}, false)
	defer server.Close()

	f := &Fetcher{Slug: "jclement/devtun", Version: "v0.1.0", CacheDir: t.TempDir(), BaseURL: server.URL}

	_, err := f.Binary(context.Background(), "plan9", "mips")
	if err == nil || !strings.Contains(err.Error(), "plan9/mips") {
		t.Errorf("want a message naming the platform, got %v", err)
	}
}

// goreleaser writes arm as armv7 in the archive name; getting that wrong is a
// 404 on the one platform nobody tests by hand.
func TestArmIsNamedArmv7(t *testing.T) {
	f := &Fetcher{Version: "v0.1.0"}
	if got := f.assetName("linux", "arm"); got != "devtun_0.1.0_linux_armv7.tar.gz" {
		t.Errorf("assetName = %q", got)
	}
	if got := f.assetName("windows", "amd64"); got != "devtun_0.1.0_windows_amd64.zip" {
		t.Errorf("windows should be a zip, got %q", got)
	}
}

// A tar is attacker-shaped input: a member named ../../devtun must not be able
// to steer where anything is written, and the base name is what is matched.
func TestExtractIgnoresPathsInMemberNames(t *testing.T) {
	archive := tarGz(t, "../../evil/devtun", []byte("payload"))

	got, err := extract(archive, "devtun")
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if string(got) != "payload" {
		t.Errorf("extract returned %q", got)
	}
}
