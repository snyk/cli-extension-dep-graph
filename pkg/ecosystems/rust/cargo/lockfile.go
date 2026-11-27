package cargo

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/BurntSushi/toml"
)

// lockPackage is one [[package]] entry of Cargo.lock. Only the fields the
// component-metadata labels need are kept; the dependency graph itself comes
// from cargo tree, never from the lockfile.
type lockPackage struct {
	Name     string
	Version  string
	Source   string
	Checksum string
}

type rawLockFile struct {
	Package []struct {
		Name     string `toml:"name"`
		Version  string `toml:"version"`
		Source   string `toml:"source"`
		Checksum string `toml:"checksum"`
	} `toml:"package"`
	// Metadata holds version 1 lockfiles' checksums, keyed
	// "checksum <name> <version> (<source>)". Cargo 1.41 moved them onto
	// each package; reading both keeps lockfiles from older toolchains
	// covered at the cost of one map lookup.
	Metadata map[string]string `toml:"metadata"`
}

const v1ChecksumKeyPrefix = "checksum "

// maxLockFileSize bounds the bytes handed to the TOML parser. Real lockfiles
// of thousands of crates are a few MiB; the cap keeps a crafted file from
// exhausting memory should one ever reach the parser.
const maxLockFileSize = 16 << 20

var errLockFileTooLarge = errors.New("lockfile exceeds the size limit")

// readLockFile reads and parses the Cargo.lock at path, refusing files over
// maxLockFileSize.
func readLockFile(path string) ([]lockPackage, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening Cargo.lock: %w", err)
	}
	defer f.Close()

	data, err := io.ReadAll(io.LimitReader(f, maxLockFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("reading Cargo.lock: %w", err)
	}
	if len(data) > maxLockFileSize {
		return nil, fmt.Errorf("%w of %d bytes", errLockFileTooLarge, maxLockFileSize)
	}
	return parseLockFile(data)
}

// parseLockFile reads the package entries of a Cargo.lock in any format
// version. Entries keep file order so callers never depend on map order.
func parseLockFile(data []byte) ([]lockPackage, error) {
	var raw rawLockFile
	if err := toml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parsing Cargo.lock: %w", err)
	}

	pkgs := make([]lockPackage, 0, len(raw.Package))
	for _, p := range raw.Package {
		checksum := p.Checksum
		if checksum == "" && p.Source != "" {
			key := fmt.Sprintf("%s%s %s (%s)", v1ChecksumKeyPrefix, p.Name, p.Version, p.Source)
			// Cargo writes "<none>" for a registry package it has no
			// checksum for; drop it so the entry reads the same as a v3/v4
			// package without one.
			if v := raw.Metadata[key]; v != "<none>" {
				checksum = v
			}
		}
		pkgs = append(pkgs, lockPackage{
			Name:     p.Name,
			Version:  p.Version,
			Source:   p.Source,
			Checksum: checksum,
		})
	}
	return pkgs, nil
}
