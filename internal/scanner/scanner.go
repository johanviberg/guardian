// Package scanner is the boundary between guardian and the underlying scan
// engine (a vendored fork of Perplexity's Bumblebee, under internal/bumblebee).
//
// Everything in guardian depends on the Scanner interface, never on bumblebee
// directly. This keeps the upstream re-sync blast radius contained to this one
// package and makes the engine swappable.
package scanner

import (
	"context"

	"github.com/johanviberg/guardian/internal/model"
)

// Options configures a single scan invocation.
type Options struct {
	Profile      model.Profile
	Roots        []string // explicit roots (required for deep, optional otherwise)
	CatalogPath  string   // path to the exposure catalog JSON
	FindingsOnly bool     // if true, skip emitting inventory components
}

// Scanner runs an inventory+exposure scan and returns typed results.
//
// Implementations:
//   - VendoredScanner: drives the in-tree bumblebee fork (internal/bumblebee).
//   - fake scanners in tests.
type Scanner interface {
	// Scan performs one scan and returns parsed, typed results.
	Scan(ctx context.Context, opts Options) (*model.ScanResult, error)

	// Version reports the underlying engine version (for ScanRun.ScannerVer).
	Version() string

	// SelfTest runs the engine's embedded end-to-end validation.
	SelfTest(ctx context.Context) error
}
