// Package store provides local SQLite persistence for guardian scan history,
// findings, catalog versions, and suppressions. It uses the pure-Go driver
// modernc.org/sqlite (no cgo), so the binary cross-compiles cleanly for macOS,
// Linux, and Windows.
//
// The schema is versioned via SQLite's user_version pragma and migrations are
// applied idempotently on Open, so reopening an existing database is safe.
package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// Store is a handle to the guardian SQLite database. It is safe for concurrent
// use by multiple goroutines (database/sql manages an internal pool).
type Store struct {
	db *sql.DB
}

// Open opens (creating if necessary) the SQLite database at path, enables
// foreign-key enforcement and WAL journaling, and applies any pending
// migrations. The caller is responsible for resolving path to an
// OS-appropriate location and ensuring its parent directory exists.
func Open(path string) (*Store, error) {
	// _pragma query args are honored by modernc.org/sqlite on every new
	// connection in the pool, so foreign keys stay enforced across the pool.
	dsn := fmt.Sprintf("file:%s?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open %q: %w", path, err)
	}
	// modernc.org/sqlite serializes within a single connection; allowing many
	// connections with WAL is fine, but keep a sane upper bound.
	db.SetMaxOpenConns(1)

	s := &Store{db: db}
	if err := s.migrate(context.Background()); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("store: migrate: %w", err)
	}
	return s, nil
}

// Close releases the underlying database handle.
func (s *Store) Close() error {
	return s.db.Close()
}

// schemaVersion is the current schema version. Bump it and append a migration
// step in migrate when the schema changes.
const schemaVersion = 1

// migrate applies migrations idempotently using SQLite's user_version pragma as
// the migration marker. Each step is wrapped in its own transaction.
func (s *Store) migrate(ctx context.Context) error {
	var current int
	if err := s.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&current); err != nil {
		return fmt.Errorf("read user_version: %w", err)
	}

	// Ordered migration steps. Index i (0-based) advances the DB from version i
	// to version i+1.
	steps := []string{
		migration1,
	}

	for v := current; v < len(steps); v++ {
		if err := s.applyMigration(ctx, v+1, steps[v]); err != nil {
			return fmt.Errorf("apply migration to v%d: %w", v+1, err)
		}
	}
	return nil
}

func (s *Store) applyMigration(ctx context.Context, version int, ddl string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, ddl); err != nil {
		return err
	}
	// PRAGMA user_version does not accept bound parameters; the value is an
	// internally-generated trusted int, so formatting it is safe.
	if _, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", version)); err != nil {
		return err
	}
	return tx.Commit()
}

const migration1 = `
CREATE TABLE IF NOT EXISTS schema_migrations (
    version    INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_runs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at      TEXT    NOT NULL,
    finished_at     TEXT    NOT NULL,
    profile         TEXT    NOT NULL,
    roots_json      TEXT    NOT NULL,
    catalog_version TEXT    NOT NULL,
    host            TEXT    NOT NULL,
    scanner_version TEXT    NOT NULL,
    exit_code       INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS components (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id      INTEGER NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    ecosystem   TEXT    NOT NULL,
    name        TEXT    NOT NULL,
    version     TEXT    NOT NULL,
    source_file TEXT    NOT NULL,
    confidence  REAL    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_components_run ON components(run_id);

CREATE TABLE IF NOT EXISTS findings (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id        INTEGER NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    catalog_id    TEXT    NOT NULL,
    ecosystem     TEXT    NOT NULL,
    name          TEXT    NOT NULL,
    version       TEXT    NOT NULL,
    severity      TEXT    NOT NULL,
    evidence_type TEXT    NOT NULL,
    confidence    REAL    NOT NULL,
    class         TEXT    NOT NULL,
    source_file   TEXT    NOT NULL,
    suppressed    INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_findings_run ON findings(run_id);

CREATE TABLE IF NOT EXISTS catalog_versions (
    version     TEXT PRIMARY KEY,
    fetched_at  TEXT    NOT NULL,
    entry_count INTEGER NOT NULL,
    sha256      TEXT    NOT NULL,
    source_url  TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS suppressions (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ecosystem     TEXT NOT NULL,
    name          TEXT NOT NULL,
    version_range TEXT NOT NULL,
    reason        TEXT NOT NULL,
    expires_at    TEXT,
    created_at    TEXT NOT NULL
);
`

// timeFormat is the canonical on-disk timestamp format: RFC3339 with
// nanoseconds, in UTC, which sorts lexicographically in chronological order.
const timeFormat = time.RFC3339Nano

func formatTime(t time.Time) string {
	return t.UTC().Format(timeFormat)
}

func parseTime(s string) (time.Time, error) {
	return time.Parse(timeFormat, s)
}
