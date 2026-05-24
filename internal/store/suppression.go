package store

import (
	"context"
	"database/sql"
	"time"
)

// Suppression is a stored acknowledgement of a finding with an optional expiry,
// mirroring the suppressions table. A nil ExpiresAt means the suppression never
// expires.
type Suppression struct {
	ID           int64      `json:"id"`
	Ecosystem    string     `json:"ecosystem"`
	Name         string     `json:"name"`
	VersionRange string     `json:"version_range"`
	Reason       string     `json:"reason"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
}

// AddSuppression inserts a suppression and returns its new id. CreatedAt is set
// to the current time if the caller left it zero. A nil expiresAt stores NULL
// (never expires).
func (s *Store) AddSuppression(ctx context.Context, sup Suppression) (int64, error) {
	createdAt := sup.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now()
	}

	var expires any
	if sup.ExpiresAt != nil {
		expires = formatTime(*sup.ExpiresAt)
	}

	res, err := s.db.ExecContext(ctx, `
		INSERT INTO suppressions (ecosystem, name, version_range, reason, expires_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?)`,
		sup.Ecosystem, sup.Name, sup.VersionRange, sup.Reason, expires, formatTime(createdAt),
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// ActiveSuppressions returns suppressions that have not expired: those whose
// expires_at is NULL or strictly in the future relative to now.
func (s *Store) ActiveSuppressions(ctx context.Context) ([]Suppression, error) {
	now := formatTime(time.Now())
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, ecosystem, name, version_range, reason, expires_at, created_at
		FROM suppressions
		WHERE expires_at IS NULL OR expires_at > ?
		ORDER BY id ASC`, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Suppression
	for rows.Next() {
		sup, err := scanSuppression(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sup)
	}
	return out, rows.Err()
}

// PruneExpiredSuppressions deletes suppressions whose expires_at is in the past
// (NULL/never-expiring rows are kept) and returns the number deleted.
func (s *Store) PruneExpiredSuppressions(ctx context.Context) (int64, error) {
	now := formatTime(time.Now())
	res, err := s.db.ExecContext(ctx, `
		DELETE FROM suppressions
		WHERE expires_at IS NOT NULL AND expires_at <= ?`, now)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func scanSuppression(rows *sql.Rows) (Suppression, error) {
	var (
		sup       Suppression
		expires   sql.NullString
		createdAt string
	)
	if err := rows.Scan(&sup.ID, &sup.Ecosystem, &sup.Name, &sup.VersionRange,
		&sup.Reason, &expires, &createdAt); err != nil {
		return Suppression{}, err
	}
	if expires.Valid {
		t, err := parseTime(expires.String)
		if err != nil {
			return Suppression{}, err
		}
		sup.ExpiresAt = &t
	}
	t, err := parseTime(createdAt)
	if err != nil {
		return Suppression{}, err
	}
	sup.CreatedAt = t
	return sup, nil
}
