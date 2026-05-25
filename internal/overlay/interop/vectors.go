// Package interop implements a Go conformance vector runner that consumes the
// pinned ts-stack conformance corpus (docs/internal/conformance-vectors/) and
// reports per-vector pass/fail status.
//
// See docs/internal/OVERLAY_PROTOCOL_ALIGNMENT_PLAN.md §Workstream F.
package interop

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// ParityClass mirrors conformance/schema/vector.schema.json #/properties/parity_class.
type ParityClass string

const (
	ParityRequired   ParityClass = "required"
	ParityIntended   ParityClass = "intended"
	ParityBestEffort ParityClass = "best-effort"
	ParityUnsupported ParityClass = "unsupported"
)

// VectorFile is the top-level shape of a JSON vector file.
// Mirrors conformance/schema/vector.schema.json.
type VectorFile struct {
	Schema        string      `json:"$schema,omitempty"`
	ID            string      `json:"id"`
	Name          string      `json:"name"`
	BRC           []string    `json:"brc,omitempty"`
	Version       string      `json:"version"`
	ReferenceImpl string      `json:"reference_impl"`
	ParityClass   ParityClass `json:"parity_class"`
	Description   string      `json:"description,omitempty"`
	Vectors       []Vector    `json:"vectors"`

	// SourcePath is the on-disk path the file was loaded from; not in JSON.
	SourcePath string `json:"-"`
}

// Vector is one test case inside a VectorFile.
type Vector struct {
	ID          string          `json:"id"`
	Description string          `json:"description"`
	Input       json.RawMessage `json:"input"`
	Expected    json.RawMessage `json:"expected"`
	Tags        []string        `json:"tags,omitempty"`
	Skip        bool            `json:"skip,omitempty"`
	SkipReason  string          `json:"skip_reason,omitempty"`
}

// LoadAll walks rootDir and returns every parsed *.json vector file under it.
// rootDir is expected to be docs/internal/conformance-vectors/ (relative to
// the Anvil repo root, or absolute). Non-vector JSON files (META.json,
// schema/vector.schema.json) are filtered out by shape: a vector file must
// have a non-empty Vectors array.
func LoadAll(rootDir string) ([]*VectorFile, error) {
	var files []*VectorFile

	walkErr := filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if filepath.Ext(path) != ".json" {
			return nil
		}

		// Skip schema and corpus-metadata files; only load vector files.
		base := filepath.Base(path)
		rel, _ := filepath.Rel(rootDir, path)
		if base == "META.json" || base == "vector.schema.json" {
			return nil
		}
		// Anything inside schema/ is schema-side, not a vector file.
		if dir := filepath.Dir(rel); dir == "schema" {
			return nil
		}

		vf, err := loadFile(path)
		if err != nil {
			return fmt.Errorf("load %s: %w", path, err)
		}
		// Defensive: require the file to actually contain vectors. Anything
		// shaped like a vector file but with no vectors is suspicious and worth
		// flagging during Phase 0a.
		if len(vf.Vectors) == 0 {
			return fmt.Errorf("vector file has empty vectors array: %s", path)
		}
		vf.SourcePath = path
		files = append(files, vf)
		return nil
	})
	if walkErr != nil {
		return nil, walkErr
	}

	sort.Slice(files, func(i, j int) bool {
		return files[i].ID < files[j].ID
	})
	return files, nil
}

func loadFile(path string) (*VectorFile, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var vf VectorFile
	if err := json.Unmarshal(raw, &vf); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	if vf.ID == "" {
		return nil, fmt.Errorf("vector file missing required field: id")
	}
	return &vf, nil
}

// TotalVectors counts every vector across files, including skipped ones.
func TotalVectors(files []*VectorFile) int {
	n := 0
	for _, f := range files {
		n += len(f.Vectors)
	}
	return n
}

// ActiveVectors counts only the vectors a conforming run should execute
// (excludes Skip=true).
func ActiveVectors(files []*VectorFile) int {
	n := 0
	for _, f := range files {
		for _, v := range f.Vectors {
			if !v.Skip {
				n++
			}
		}
	}
	return n
}
