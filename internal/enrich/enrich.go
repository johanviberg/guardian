// Package enrich defines guardian's optional vulnerability-enrichment contract.
//
// Enrichment is OPT-IN and OFF BY DEFAULT. An Enricher takes the inventory of
// components a scan discovered and returns additional findings drawn from an
// external advisory database (e.g. OSV). Enrichment findings are treated as
// INFORMATIONAL by default by internal/policy and never escalate a scan's exit
// code unless the operator opts into gating.
//
// Enrichment must never fail a scan: an Enricher returns its findings together
// with a soft error (see SoftError) on network/offline/rate-limit failures so
// the caller can warn and proceed with whatever findings were gathered.
package enrich

import (
	"context"

	"github.com/johanviberg/guardian/internal/model"
)

// Enricher augments a component inventory with findings from an external source.
type Enricher interface {
	// Enrich returns findings for the supplied components. Implementations skip
	// components they cannot map (unsupported ecosystem, missing version) and
	// must not return an error type that would abort the scan: transient/network
	// failures should be reported as a SoftError so the caller can warn and
	// proceed with any partial results.
	Enrich(ctx context.Context, comps []model.Component) ([]model.Finding, error)
	// Name is a short stable identifier for the enricher, e.g. "osv".
	Name() string
}

// SoftError wraps a non-fatal enrichment failure (offline, timeout, rate limit).
// The caller should warn and proceed with whatever findings were returned rather
// than failing the scan.
type SoftError struct {
	// Source is the enricher name that produced the error.
	Source string
	// Err is the underlying cause.
	Err error
}

func (e *SoftError) Error() string {
	return e.Source + " enrichment degraded: " + e.Err.Error()
}

func (e *SoftError) Unwrap() error { return e.Err }
