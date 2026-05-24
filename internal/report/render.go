package report

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/johanviberg/guardian/internal/model"
)

// Counts summarises findings by severity for headline display.
type Counts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

// CountFindings tallies findings by severity. Suppressed findings are counted
// but callers may choose to render them separately.
func CountFindings(findings []model.Finding) Counts {
	var c Counts
	for _, f := range findings {
		switch f.Severity {
		case model.SeverityCritical:
			c.Critical++
		case model.SeverityHigh:
			c.High++
		case model.SeverityMedium:
			c.Medium++
		case model.SeverityLow:
			c.Low++
		case model.SeverityInfo:
			c.Info++
		}
	}
	return c
}

// Total returns the sum across all severities.
func (c Counts) Total() int { return c.Critical + c.High + c.Medium + c.Low + c.Info }

// StatusView is the data backing RenderStatus and the `status` JSON payload.
type StatusView struct {
	Host           string          `json:"host"`
	CatalogVersion string          `json:"catalog_version"`
	CatalogFresh   bool            `json:"catalog_fresh"`
	LastScanAt     time.Time       `json:"last_scan_at"`
	Findings       []model.Finding `json:"findings"`
	Counts         Counts          `json:"counts"`
}

// ScanView is the data backing RenderScan and the `scan` JSON payload.
type ScanView struct {
	Profile        model.Profile   `json:"profile"`
	Host           string          `json:"host"`
	CatalogVersion string          `json:"catalog_version"`
	ScannedAt      time.Time       `json:"scanned_at"`
	ComponentCount int             `json:"component_count"`
	Findings       []model.Finding `json:"findings"`
	Counts         Counts          `json:"counts"`
	ExitCode       int             `json:"exit_code"`
}

// DiffView is the data backing RenderDiff and the `diff` JSON payload.
type DiffView struct {
	New        []model.Finding `json:"new"`
	Resolved   []model.Finding `json:"resolved"`
	Persisting []model.Finding `json:"persisting"`
}

// Renderer holds rendering options shared across the human renderers.
type Renderer struct {
	// EnableColor turns on simple ANSI coloring of severities. Default off.
	EnableColor bool
}

// RenderScan writes the human-readable result of a scan to w.
func (r Renderer) RenderScan(w io.Writer, v ScanView) error {
	fmt.Fprintf(w, "guardian scan (%s) on %s\n", v.Profile, v.Host)
	fmt.Fprintf(w, "catalog %s · %d components scanned · %s\n",
		dash(v.CatalogVersion), v.ComponentCount, formatTime(v.ScannedAt))
	fmt.Fprintln(w)
	r.renderFindingGroups(w, v.Findings)
	fmt.Fprintln(w)
	fmt.Fprintf(w, "%s\n", r.summaryLine(v.Counts))
	fmt.Fprintf(w, "exit code: %d (%s)\n", v.ExitCode, exitRationale(v.ExitCode))
	return nil
}

// RenderStatus writes the human-readable current status to w.
func (r Renderer) RenderStatus(w io.Writer, v StatusView) error {
	fmt.Fprintf(w, "guardian status — %s\n", v.Host)
	fmt.Fprintf(w, "catalog:   %s (%s)\n", dash(v.CatalogVersion), freshLabel(v.CatalogFresh))
	fmt.Fprintf(w, "last scan: %s\n", formatTime(v.LastScanAt))
	fmt.Fprintln(w)
	if len(v.Findings) == 0 {
		fmt.Fprintln(w, "no active exposures.")
		return nil
	}
	r.renderFindingGroups(w, v.Findings)
	fmt.Fprintln(w)
	fmt.Fprintf(w, "%s\n", r.summaryLine(v.Counts))
	return nil
}

// RenderDiff writes the human-readable diff between two runs to w.
func (r Renderer) RenderDiff(w io.Writer, v DiffView) error {
	fmt.Fprintln(w, "guardian diff")
	fmt.Fprintf(w, "%d new · %d resolved · %d persisting\n",
		len(v.New), len(v.Resolved), len(v.Persisting))
	fmt.Fprintln(w)

	r.renderDiffBucket(w, "NEW", "+", v.New)
	r.renderDiffBucket(w, "RESOLVED", "-", v.Resolved)
	r.renderDiffBucket(w, "PERSISTING", "·", v.Persisting)
	return nil
}

// renderFindingGroups prints findings grouped by class then severity, in a
// stable order, as an aligned table per group.
func (r Renderer) renderFindingGroups(w io.Writer, findings []model.Finding) {
	if len(findings) == 0 {
		fmt.Fprintln(w, "no findings.")
		return
	}
	byClass := groupByClass(findings)
	for _, class := range classOrder {
		group := byClass[class]
		if len(group) == 0 {
			continue
		}
		fmt.Fprintf(w, "%s (%d)\n", classLabel(class), len(group))
		r.renderFindingTable(w, group)
		fmt.Fprintln(w)
	}
}

func (r Renderer) renderFindingTable(w io.Writer, findings []model.Finding) {
	sortFindings(findings)
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	for _, f := range findings {
		sup := ""
		if f.Suppressed {
			sup = " (suppressed)"
		}
		fmt.Fprintf(tw, "  %s\t%s\t%s@%s\t%s%s\n",
			r.severityTag(f.Severity), f.CatalogID,
			ecoName(f), f.Version, f.SourceFile, sup)
	}
	_ = tw.Flush()
}

func (r Renderer) renderDiffBucket(w io.Writer, title, marker string, findings []model.Finding) {
	if len(findings) == 0 {
		return
	}
	fmt.Fprintf(w, "%s (%d)\n", title, len(findings))
	sortFindings(findings)
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	for _, f := range findings {
		fmt.Fprintf(tw, "  %s %s\t%s\t%s@%s\t%s\n",
			marker, r.severityTag(f.Severity), f.CatalogID,
			ecoName(f), f.Version, f.SourceFile)
	}
	_ = tw.Flush()
	fmt.Fprintln(w)
}

func (r Renderer) summaryLine(c Counts) string {
	if c.Total() == 0 {
		return "clean: no findings."
	}
	parts := []string{}
	add := func(n int, label string) {
		if n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, label))
		}
	}
	add(c.Critical, "critical")
	add(c.High, "high")
	add(c.Medium, "medium")
	add(c.Low, "low")
	add(c.Info, "info")
	return "findings: " + strings.Join(parts, ", ")
}

// ----- helpers -----

var classOrder = []model.Class{
	model.ClassConfirmedMalicious,
	model.ClassVulnerable,
	model.ClassInformational,
}

func classLabel(c model.Class) string {
	switch c {
	case model.ClassConfirmedMalicious:
		return "CONFIRMED MALICIOUS"
	case model.ClassVulnerable:
		return "VULNERABLE"
	case model.ClassInformational:
		return "INFORMATIONAL"
	}
	return strings.ToUpper(string(c))
}

func groupByClass(findings []model.Finding) map[model.Class][]model.Finding {
	out := map[model.Class][]model.Finding{}
	for _, f := range findings {
		out[f.Class] = append(out[f.Class], f)
	}
	return out
}

// severityRank orders severities from most to least urgent for sorting.
func severityRank(s model.Severity) int {
	switch s {
	case model.SeverityCritical:
		return 0
	case model.SeverityHigh:
		return 1
	case model.SeverityMedium:
		return 2
	case model.SeverityLow:
		return 3
	case model.SeverityInfo:
		return 4
	}
	return 5
}

// sortFindings orders by severity, then catalog id, then name, for stable
// deterministic output (golden-test friendly).
func sortFindings(f []model.Finding) {
	sort.SliceStable(f, func(i, j int) bool {
		if ri, rj := severityRank(f[i].Severity), severityRank(f[j].Severity); ri != rj {
			return ri < rj
		}
		if f[i].CatalogID != f[j].CatalogID {
			return f[i].CatalogID < f[j].CatalogID
		}
		if f[i].Name != f[j].Name {
			return f[i].Name < f[j].Name
		}
		return f[i].Version < f[j].Version
	})
}

func ecoName(f model.Finding) string {
	if f.Ecosystem == "" {
		return f.Name
	}
	return f.Ecosystem + ":" + f.Name
}

func (r Renderer) severityTag(s model.Severity) string {
	tag := "[" + strings.ToUpper(string(s)) + "]"
	if !r.EnableColor {
		return tag
	}
	return colorize(s, tag)
}

func colorize(s model.Severity, text string) string {
	const reset = "\x1b[0m"
	var code string
	switch s {
	case model.SeverityCritical:
		code = "\x1b[1;31m" // bold red
	case model.SeverityHigh:
		code = "\x1b[31m" // red
	case model.SeverityMedium:
		code = "\x1b[33m" // yellow
	case model.SeverityLow:
		code = "\x1b[36m" // cyan
	default:
		code = "\x1b[2m" // dim
	}
	return code + text + reset
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func freshLabel(fresh bool) string {
	if fresh {
		return "fresh"
	}
	return "STALE"
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return t.UTC().Format("2006-01-02 15:04:05 MST")
}

// exitRationale explains a guardian exit code for the human scan footer.
func exitRationale(code int) string {
	switch code {
	case 0:
		return "clean"
	case 1:
		return "non-critical findings"
	case 2:
		return "confirmed-malicious / critical findings"
	default:
		return "unknown"
	}
}
