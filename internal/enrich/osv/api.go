package osv

// OSV REST API request/response shapes. Only the fields guardian consumes are
// modeled; OSV returns more (and may add fields), which JSON decoding ignores.

// batchRequest is the body of POST /v1/querybatch.
type batchRequest struct {
	Queries []batchQuery `json:"queries"`
}

type batchQuery struct {
	Package batchPackage `json:"package"`
	Version string       `json:"version,omitempty"`
}

type batchPackage struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}

// batchResponse is the body of the querybatch response; Results aligns by index
// with the request Queries. An entry may have no Vulns.
type batchResponse struct {
	Results []batchResult `json:"results"`
}

type batchResult struct {
	Vulns []batchVuln `json:"vulns"`
}

type batchVuln struct {
	ID       string `json:"id"`
	Modified string `json:"modified"`
}

// vulnDetail is the body of GET /v1/vulns/{id}.
type vulnDetail struct {
	ID               string           `json:"id"`
	Aliases          []string         `json:"aliases"`
	Summary          string           `json:"summary"`
	Details          string           `json:"details"`
	Severity         []severityEntry  `json:"severity"`
	DatabaseSpecific databaseSpecific `json:"database_specific"`
	Modified         string           `json:"modified"`
}

type severityEntry struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type databaseSpecific struct {
	Severity string `json:"severity"`
}
