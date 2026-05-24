package store

import (
	"context"
	"time"
)

// PruneComponents deletes component (inventory) rows belonging to runs that
// started before olderThan, returning the number of component rows removed.
// Findings and the scan_run metadata are intentionally retained — the design
// keeps findings longer than the inventory they were derived from.
func (s *Store) PruneComponents(ctx context.Context, olderThan time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `
		DELETE FROM components
		WHERE run_id IN (SELECT id FROM scan_runs WHERE started_at < ?)`,
		formatTime(olderThan))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
