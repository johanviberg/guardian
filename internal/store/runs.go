package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/johanviberg/guardian/internal/model"
)

// SaveRun inserts a scan run together with its components and findings inside a
// single transaction and returns the new run id. The run argument is not
// mutated; the returned id is also assigned to a copy only via the return value.
func (s *Store) SaveRun(ctx context.Context, run *model.ScanRun) (int64, error) {
	if run == nil {
		return 0, errors.New("store: SaveRun: nil run")
	}

	rootsJSON, err := json.Marshal(run.Roots)
	if err != nil {
		return 0, fmt.Errorf("store: marshal roots: %w", err)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	res, err := tx.ExecContext(ctx, `
		INSERT INTO scan_runs
			(started_at, finished_at, profile, roots_json, catalog_version, host, scanner_version, exit_code)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		formatTime(run.StartedAt), formatTime(run.FinishedAt), string(run.Profile),
		string(rootsJSON), run.CatalogVer, run.Host, run.ScannerVer, run.ExitCode,
	)
	if err != nil {
		return 0, fmt.Errorf("store: insert scan_run: %w", err)
	}
	runID, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}

	for i, c := range run.Components {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO components (run_id, ecosystem, name, version, source_file, confidence)
			VALUES (?, ?, ?, ?, ?, ?)`,
			runID, c.Ecosystem, c.Name, c.Version, c.SourceFile, c.Confidence,
		); err != nil {
			return 0, fmt.Errorf("store: insert component %d: %w", i, err)
		}
	}

	for i, f := range run.Findings {
		source := f.Source
		if source == "" {
			source = model.SourceCatalog
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO findings
				(run_id, catalog_id, ecosystem, name, version, severity, evidence_type, confidence, class, source_file, suppressed, source, summary)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			runID, f.CatalogID, f.Ecosystem, f.Name, f.Version, string(f.Severity),
			f.EvidenceType, f.Confidence, string(f.Class), f.SourceFile, boolToInt(f.Suppressed),
			string(source), f.Summary,
		); err != nil {
			return 0, fmt.Errorf("store: insert finding %d: %w", i, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return runID, nil
}

// GetRun loads a single run by id with its components and findings populated.
// It returns (nil, nil) if no run with that id exists.
func (s *Store) GetRun(ctx context.Context, id int64) (*model.ScanRun, error) {
	row := s.db.QueryRowContext(ctx, scanRunSelect+` WHERE id = ?`, id)
	run, err := scanRunFromRow(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	if err := s.loadChildren(ctx, run); err != nil {
		return nil, err
	}
	return run, nil
}

// LatestRun returns the most recent run (highest id) with children populated,
// or (nil, nil) if no runs exist.
func (s *Store) LatestRun(ctx context.Context) (*model.ScanRun, error) {
	row := s.db.QueryRowContext(ctx, scanRunSelect+` ORDER BY id DESC LIMIT 1`)
	run, err := scanRunFromRow(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	if err := s.loadChildren(ctx, run); err != nil {
		return nil, err
	}
	return run, nil
}

// PreviousRun returns the most recent run with an id strictly less than
// beforeRunID, with children populated, or (nil, nil) if there is none.
func (s *Store) PreviousRun(ctx context.Context, beforeRunID int64) (*model.ScanRun, error) {
	row := s.db.QueryRowContext(ctx, scanRunSelect+` WHERE id < ? ORDER BY id DESC LIMIT 1`, beforeRunID)
	run, err := scanRunFromRow(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	if err := s.loadChildren(ctx, run); err != nil {
		return nil, err
	}
	return run, nil
}

// RunsSince returns run metadata (no components or findings) for every run
// started at or after since, ordered oldest-first. It powers `diff --since`.
func (s *Store) RunsSince(ctx context.Context, since time.Time) ([]model.ScanRun, error) {
	rows, err := s.db.QueryContext(ctx, scanRunSelect+` WHERE started_at >= ? ORDER BY id ASC`, formatTime(since))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var runs []model.ScanRun
	for rows.Next() {
		run, err := scanRunScan(rows)
		if err != nil {
			return nil, err
		}
		runs = append(runs, *run)
	}
	return runs, rows.Err()
}

const scanRunSelect = `
	SELECT id, started_at, finished_at, profile, roots_json, catalog_version, host, scanner_version, exit_code
	FROM scan_runs`

// rowScanner abstracts *sql.Row and *sql.Rows for shared scanning.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanRunFromRow(r *sql.Row) (*model.ScanRun, error) {
	return scanRunScan(r)
}

func scanRunScan(r rowScanner) (*model.ScanRun, error) {
	var (
		run        model.ScanRun
		startedAt  string
		finishedAt string
		profile    string
		rootsJSON  string
	)
	if err := r.Scan(&run.ID, &startedAt, &finishedAt, &profile, &rootsJSON,
		&run.CatalogVer, &run.Host, &run.ScannerVer, &run.ExitCode); err != nil {
		return nil, err
	}

	var err error
	if run.StartedAt, err = parseTime(startedAt); err != nil {
		return nil, fmt.Errorf("store: parse started_at: %w", err)
	}
	if run.FinishedAt, err = parseTime(finishedAt); err != nil {
		return nil, fmt.Errorf("store: parse finished_at: %w", err)
	}
	run.Profile = model.Profile(profile)
	if err := json.Unmarshal([]byte(rootsJSON), &run.Roots); err != nil {
		return nil, fmt.Errorf("store: unmarshal roots: %w", err)
	}
	return &run, nil
}

func (s *Store) loadChildren(ctx context.Context, run *model.ScanRun) error {
	comps, err := s.componentsForRun(ctx, run.ID)
	if err != nil {
		return err
	}
	run.Components = comps

	finds, err := s.findingsForRun(ctx, run.ID)
	if err != nil {
		return err
	}
	run.Findings = finds
	return nil
}

func (s *Store) componentsForRun(ctx context.Context, runID int64) ([]model.Component, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT ecosystem, name, version, source_file, confidence
		FROM components WHERE run_id = ? ORDER BY id ASC`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []model.Component
	for rows.Next() {
		var c model.Component
		if err := rows.Scan(&c.Ecosystem, &c.Name, &c.Version, &c.SourceFile, &c.Confidence); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) findingsForRun(ctx context.Context, runID int64) ([]model.Finding, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT catalog_id, ecosystem, name, version, severity, evidence_type, confidence, class, source_file, suppressed, source, summary
		FROM findings WHERE run_id = ? ORDER BY id ASC`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []model.Finding
	for rows.Next() {
		var (
			f          model.Finding
			severity   string
			class      string
			suppressed int
			source     string
		)
		if err := rows.Scan(&f.CatalogID, &f.Ecosystem, &f.Name, &f.Version, &severity,
			&f.EvidenceType, &f.Confidence, &class, &f.SourceFile, &suppressed, &source, &f.Summary); err != nil {
			return nil, err
		}
		f.Severity = model.Severity(severity)
		f.Class = model.Class(class)
		f.Suppressed = suppressed != 0
		if source == "" {
			source = string(model.SourceCatalog)
		}
		f.Source = model.Source(source)
		out = append(out, f)
	}
	return out, rows.Err()
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
