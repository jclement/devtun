// Package release fetches a devtun binary built for another platform.
//
// It exists because of a gap that only shows up in a released build. The helper
// devtun uploads has to run on the *remote* box, which is almost never the
// platform the workstation runs: a Mac talking to a Linux dev box needs a
// linux/arm64 binary, and it has no way to produce one. A development checkout
// can cross-build into dist/ and does; somebody who installed from Homebrew
// cannot, and without this they get a message telling them to run a mise task
// in a repository they have never cloned — and two of the four services
// silently do not work.
//
// So the binary is downloaded from the same GitHub release this build came
// from. That is a binary fetched over the network and then executed on another
// machine, which deserves the care below: it is checked against the checksums
// published with that release, and the version is pinned to this build's own
// rather than "latest", so a devtun cannot be talked into installing a helper
// from a release it knows nothing about.
package release

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	// downloadTimeout bounds the whole fetch. A helper that cannot be had in a
	// couple of minutes is one the user should hear about, not wait on.
	downloadTimeout = 2 * time.Minute
	// maxAsset caps what will be read from the network. The archives are a few
	// megabytes; anything near this is not one of ours.
	maxAsset = 64 << 20
)

// Fetcher downloads release assets.
type Fetcher struct {
	// Slug is the GitHub repository, "owner/name".
	Slug string
	// Version is the release to take the helper from — this build's own, not
	// the newest. A devtun that fetched "latest" could be handed a helper from
	// a release it has never heard of.
	Version string
	// CacheDir holds fetched helpers so a reconnect, or tomorrow, does not
	// download again. Empty uses the user cache directory.
	CacheDir string
	// BaseURL is where releases are downloaded from; tests point it elsewhere.
	BaseURL string
	// Client is the HTTP client, for tests.
	Client *http.Client
}

// ErrNoRelease means this build has no release to fetch from — a `go build`
// with no version stamped in, most often.
var ErrNoRelease = errors.New("this build has no release to download a helper from")

// Binary returns a path to a devtun binary for the given platform, downloading
// and verifying it if it is not already cached.
func (f *Fetcher) Binary(ctx context.Context, goos, goarch string) (string, error) {
	if f.Version == "" || f.Version == "dev" {
		return "", ErrNoRelease
	}

	cached, err := f.cachePath(goos, goarch)
	if err != nil {
		return "", err
	}
	if info, err := os.Stat(cached); err == nil && info.Size() > 0 {
		return cached, nil
	}

	ctx, cancel := context.WithTimeout(ctx, downloadTimeout)
	defer cancel()

	// The checksums come first: there is no point spending a download on an
	// archive there is no way to check.
	sums, err := f.checksums(ctx)
	if err != nil {
		return "", err
	}

	name := f.assetName(goos, goarch)
	want, ok := sums[name]
	if !ok {
		return "", fmt.Errorf("release %s publishes no %s; devtun cannot install a helper for %s/%s",
			f.Version, name, goos, goarch)
	}

	archive, err := f.download(ctx, name)
	if err != nil {
		return "", err
	}

	got := sha256.Sum256(archive)
	if hex.EncodeToString(got[:]) != want {
		// Not a retry-worthy failure. A checksum that does not match is either
		// a corrupted download or something worse, and the difference is not
		// knowable from here — so refuse rather than guess.
		return "", fmt.Errorf("%s does not match the checksum published with release %s; refusing to install it",
			name, f.Version)
	}

	binary, err := extract(archive, "devtun")
	if err != nil {
		return "", err
	}
	return cached, write(cached, binary)
}

// assetName is what goreleaser called the archive for a platform.
func (f *Fetcher) assetName(goos, goarch string) string {
	ext := "tar.gz"
	if goos == "windows" {
		ext = "zip"
	}
	// goreleaser writes arm as "armv7" in the archive name.
	if goarch == "arm" {
		goarch = "armv7"
	}
	return fmt.Sprintf("devtun_%s_%s_%s.%s", strings.TrimPrefix(f.Version, "v"), goos, goarch, ext)
}

// checksums fetches and parses checksums.txt from the release.
func (f *Fetcher) checksums(ctx context.Context) (map[string]string, error) {
	body, err := f.download(ctx, "checksums.txt")
	if err != nil {
		return nil, fmt.Errorf("fetching the checksums for release %s: %w", f.Version, err)
	}
	sums := map[string]string{}
	for _, line := range strings.Split(string(body), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		sums[strings.TrimPrefix(fields[1], "*")] = fields[0]
	}
	if len(sums) == 0 {
		return nil, fmt.Errorf("release %s published an unreadable checksums.txt", f.Version)
	}
	return sums, nil
}

// download fetches one asset from the release.
func (f *Fetcher) download(ctx context.Context, name string) ([]byte, error) {
	base := f.BaseURL
	if base == "" {
		base = "https://github.com"
	}
	url := fmt.Sprintf("%s/%s/releases/download/%s/%s", strings.TrimSuffix(base, "/"), f.Slug, f.Version, name)

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	client := f.Client
	if client == nil {
		client = http.DefaultClient
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("downloading %s: %w", name, err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("downloading %s: %s", name, response.Status)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxAsset))
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", name, err)
	}
	return body, nil
}

// extract pulls one file out of a .tar.gz.
func extract(archive []byte, want string) ([]byte, error) {
	gz, err := gzip.NewReader(strings.NewReader(string(archive)))
	if err != nil {
		return nil, fmt.Errorf("the downloaded archive is not gzip: %w", err)
	}
	defer gz.Close()

	reader := tar.NewReader(gz)
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("the archive contains no %q", want)
		}
		if err != nil {
			return nil, fmt.Errorf("reading the archive: %w", err)
		}
		// Compare the base name, and never join the archive's path onto a
		// directory: a tar is attacker-shaped input and "../" in a member name
		// is the oldest trick there is.
		if filepath.Base(header.Name) != want || header.Typeflag != tar.TypeReg {
			continue
		}
		return io.ReadAll(io.LimitReader(reader, maxAsset))
	}
}

// cachePath is where a fetched helper is kept between runs.
func (f *Fetcher) cachePath(goos, goarch string) (string, error) {
	dir := f.CacheDir
	if dir == "" {
		base, err := os.UserCacheDir()
		if err != nil {
			return "", fmt.Errorf("locating the cache directory: %w", err)
		}
		dir = filepath.Join(base, "devtun")
	}
	// The version is in the path so an upgrade fetches afresh rather than
	// uploading last month's helper for ever.
	return filepath.Join(dir, "helpers", f.Version, goos+"-"+goarch, "devtun"), nil
}

// write saves the helper, executable, via a temporary file so an interrupted
// download cannot leave a half-written binary to be uploaded.
func write(path string, body []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("creating %s: %w", filepath.Dir(path), err)
	}
	temp, err := os.CreateTemp(filepath.Dir(path), ".devtun-*")
	if err != nil {
		return err
	}
	name := temp.Name()
	defer os.Remove(name)

	if _, err := temp.Write(body); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(name, 0o755); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// Platform reports this build's own platform, for the case where the remote
// happens to match and nothing needs downloading.
func Platform() (goos, goarch string) { return runtime.GOOS, runtime.GOARCH }
