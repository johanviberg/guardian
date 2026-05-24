package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/johanviberg/guardian/internal/catalog"
	"github.com/johanviberg/guardian/internal/catalog/builtin"
	"github.com/johanviberg/guardian/internal/config"
	"github.com/johanviberg/guardian/internal/diff"
	"github.com/johanviberg/guardian/internal/model"
	"github.com/johanviberg/guardian/internal/notify"
	"github.com/johanviberg/guardian/internal/policy"
	"github.com/johanviberg/guardian/internal/report"
	"github.com/johanviberg/guardian/internal/scanner"
	"github.com/johanviberg/guardian/internal/store"
)

// scanFlags holds the user-facing flags that influence a scan pipeline run.
type scanFlags struct {
	roots        []string
	catalogPath  string // explicit catalog override; bypasses fetch when set
	findingsOnly bool
	json         bool
	notify       bool
	noFetch      bool
}

// scanOutcome bundles everything a single pipeline run produces, so callers
// (scan command, daemon loop) can render, notify, and decide exit codes.
type scanOutcome struct {
	cfg        *config.Config
	result     *model.ScanResult
	run        *model.ScanRun
	diff       diff.Result
	exitCode   int
	catalogVer string
	stale      bool // catalog was stale/offline but usable
}

// loadConfig loads the layered config, applies CLI overrides, and validates it.
func loadConfig(roots []string) (*config.Config, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}
	if len(roots) > 0 {
		if err := config.ApplyFlagOverrides(cfg, map[string]any{
			config.FlagScanRoots: roots,
		}); err != nil {
			return nil, err
		}
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// newCatalogManager builds a catalog.Manager from config, honoring --no-fetch.
// The embedded baseline catalogs are materialized to the cache dir and used as
// the offline default, so a scan succeeds on a fresh machine with no network.
func newCatalogManager(cfg *config.Config, noFetch bool) (*catalog.Manager, error) {
	defaultDir, err := builtin.Materialize(cfg.Catalog.CacheDir)
	if err != nil {
		// Non-fatal: fall back to whatever the manager can fetch/cache.
		defaultDir = ""
	}
	return catalog.NewManager(catalog.Config{
		CacheDir:          cfg.Catalog.CacheDir,
		SourceURL:         cfg.Catalog.SourceURL,
		TTL:               cfg.Catalog.FreshnessTTL,
		NoFetch:           noFetch,
		DefaultCatalogDir: defaultDir,
		HTTPClient:        &http.Client{Timeout: 30 * time.Second},
	})
}

// ensureCatalog resolves the catalog path + version for a scan. When the caller
// supplied an explicit --catalog path, that path is used verbatim with no fetch.
// Otherwise the Manager ensures a cached copy; a stale/offline-but-usable
// catalog is tolerated (stale=true) and only a total absence is fatal.
func ensureCatalog(ctx context.Context, cfg *config.Config, override string, noFetch bool, warn io.Writer) (path, version string, stale bool, err error) {
	if override != "" {
		return override, "(override)", false, nil
	}
	mgr, err := newCatalogManager(cfg, noFetch)
	if err != nil {
		return "", "", false, err
	}
	path, version, err = mgr.Ensure(ctx)
	if err != nil {
		if errors.Is(err, catalog.ErrStale) {
			fmt.Fprintf(warn, "guardian: warning: %v\n", err)
			return path, version, true, nil
		}
		return "", "", false, fmt.Errorf("ensure catalog: %w", err)
	}
	return path, version, false, nil
}

// suppressorFromStore builds a policy.Suppressor from the active (non-expired)
// suppressions in the store. The store already filters expired rows.
func suppressorFromStore(ctx context.Context, st *store.Store) (policy.Suppressor, error) {
	sups, err := st.ActiveSuppressions(ctx)
	if err != nil {
		return nil, fmt.Errorf("load suppressions: %w", err)
	}
	rules := make([]policy.SuppressionRule, 0, len(sups))
	for _, s := range sups {
		rules = append(rules, policy.SuppressionRule{
			Ecosystem: s.Ecosystem,
			Name:      s.Name,
			Version:   s.VersionRange,
		})
	}
	return policy.SuppressorFromRules(rules), nil
}

// openStore opens the SQLite store, creating its parent directory.
func openStore(cfg *config.Config) (*store.Store, error) {
	if err := os.MkdirAll(filepath.Dir(cfg.DBPath), 0o750); err != nil {
		return nil, fmt.Errorf("create state dir: %w", err)
	}
	st, err := store.Open(cfg.DBPath)
	if err != nil {
		return nil, err
	}
	return st, nil
}

// runScanPipeline executes steps 1-6 of the design's scan pipeline: config (the
// caller passes the already-loaded cfg), catalog ensure, scan, classify+suppress,
// persist, and diff against the previous run. Rendering, notification, and exit
// are left to the caller so scan/run/status can present results differently.
func runScanPipeline(ctx context.Context, cfg *config.Config, profile model.Profile, f scanFlags, warn io.Writer) (*scanOutcome, error) {
	catalogPath, catalogVer, stale, err := ensureCatalog(ctx, cfg, f.catalogPath, f.noFetch, warn)
	if err != nil {
		return nil, err
	}

	sc := scanner.NewVendoredScanner()
	result, err := sc.Scan(ctx, scanner.Options{
		Profile:      profile,
		Roots:        f.roots,
		CatalogPath:  catalogPath,
		FindingsOnly: f.findingsOnly,
	})
	if err != nil {
		return nil, fmt.Errorf("scan: %w", err)
	}
	// The scanner does not populate CatalogVersion; the pipeline owns it.
	result.CatalogVersion = catalogVer

	// Classify, then load + apply suppressions.
	result.Findings = policy.ClassifyAll(result.Findings)

	st, err := openStore(cfg)
	if err != nil {
		return nil, err
	}
	defer st.Close()

	sup, err := suppressorFromStore(ctx, st)
	if err != nil {
		return nil, err
	}
	result.Findings = policy.ApplySuppressions(result.Findings, sup)

	exitCode := policy.ExitCode(result.Findings)

	run := &model.ScanRun{
		StartedAt:  result.StartedAt,
		FinishedAt: result.FinishedAt,
		Profile:    result.Profile,
		Roots:      result.Roots,
		CatalogVer: catalogVer,
		Host:       result.Host,
		ScannerVer: result.ScannerVersion,
		ExitCode:   exitCode,
		Components: result.Components,
		Findings:   result.Findings,
	}

	// Diff against the most recent prior run BEFORE saving this one.
	prev, err := st.LatestRun(ctx)
	if err != nil {
		return nil, fmt.Errorf("load previous run: %w", err)
	}

	id, err := st.SaveRun(ctx, run)
	if err != nil {
		return nil, fmt.Errorf("save run: %w", err)
	}
	run.ID = id

	// Best-effort inventory retention prune.
	if cfg.Retention.ComponentDays > 0 {
		cutoff := time.Now().AddDate(0, 0, -cfg.Retention.ComponentDays)
		_, _ = st.PruneComponents(ctx, cutoff)
	}

	d := diff.Compare(prev, run)

	return &scanOutcome{
		cfg:        cfg,
		result:     result,
		run:        run,
		diff:       d,
		exitCode:   exitCode,
		catalogVer: catalogVer,
		stale:      stale,
	}, nil
}

// renderScanOutcome writes the scan result to w in JSON or human form.
func renderScanOutcome(w io.Writer, o *scanOutcome, asJSON bool) error {
	view := report.ScanView{
		Profile:        o.result.Profile,
		Host:           o.result.Host,
		CatalogVersion: o.catalogVer,
		ScannedAt:      o.result.FinishedAt,
		ComponentCount: len(o.result.Components),
		Findings:       o.result.Findings,
		Counts:         report.CountFindings(actionable(o.result.Findings)),
		ExitCode:       o.exitCode,
	}
	if asJSON {
		return report.WriteJSON(w, "scan", view)
	}
	return report.Renderer{}.RenderScan(w, view)
}

// actionable returns findings excluding suppressed ones, for headline counts.
func actionable(findings []model.Finding) []model.Finding {
	out := make([]model.Finding, 0, len(findings))
	for _, f := range findings {
		if !f.Suppressed {
			out = append(out, f)
		}
	}
	return out
}

// dispatchNotifications builds a Dispatcher from config and fires on NEW
// findings at or above the configured threshold. It never returns a fatal
// error: notification failures are reported as warnings only.
func dispatchNotifications(ctx context.Context, cfg *config.Config, d diff.Result, warn io.Writer) {
	threshold := model.Severity(cfg.Notify.MinSeverity)

	n, send := notify.NotificationFromNew(d.New, threshold)
	if !send {
		return
	}

	notifiers := buildNotifiers(cfg)
	dispatcher := notify.NewDispatcher(notify.Config{
		Threshold:  threshold,
		QuietHours: quietHoursFromConfig(cfg.Notify.QuietHours),
	}, notifiers...)

	if err := dispatcher.Dispatch(ctx, n); err != nil {
		fmt.Fprintf(warn, "guardian: warning: notification delivery: %v\n", err)
	}
}

// buildNotifiers maps configured channels onto concrete Notifiers. Terminal is
// always available; desktop and webhook only when enabled (webhook also needs a
// URL).
func buildNotifiers(cfg *config.Config) []notify.Notifier {
	var out []notify.Notifier
	for _, ch := range cfg.Notify.Channels {
		switch ch {
		case "terminal":
			out = append(out, notify.NewTerminalNotifier(os.Stdout))
		case "desktop":
			out = append(out, notify.NewDesktopNotifier())
		case "webhook":
			if cfg.Notify.WebhookURL != "" {
				out = append(out, notify.NewWebhookNotifier(cfg.Notify.WebhookURL))
			}
		}
	}
	if len(out) == 0 {
		out = append(out, notify.NewTerminalNotifier(os.Stdout))
	}
	return out
}

// quietHoursFromConfig converts config "HH:MM" quiet hours into notify's
// minutes-since-midnight representation. Invalid values disable the window.
func quietHoursFromConfig(q config.QuietHours) notify.QuietHours {
	if !q.Enabled() {
		return notify.QuietHours{}
	}
	start, err1 := clockMinutes(q.Start)
	end, err2 := clockMinutes(q.End)
	if err1 != nil || err2 != nil {
		return notify.QuietHours{}
	}
	return notify.QuietHours{Enabled: true, Start: start, End: end}
}

func clockMinutes(s string) (int, error) {
	t, err := time.Parse("15:04", s)
	if err != nil {
		return 0, err
	}
	return t.Hour()*60 + t.Minute(), nil
}
