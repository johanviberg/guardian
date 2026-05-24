package store

import (
	"context"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/rmxventures/guardian/internal/model"
)

func tempStore(t *testing.T) *Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "guardian.db")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func sampleRun() *model.ScanRun {
	start := time.Date(2026, 5, 24, 12, 0, 0, 0, time.UTC)
	return &model.ScanRun{
		StartedAt:  start,
		FinishedAt: start.Add(2 * time.Second),
		Profile:    model.ProfileBaseline,
		Roots:      []string{"/home/user", "/opt/app"},
		CatalogVer: "2026.05.24",
		Host:       "laptop",
		ScannerVer: "bumblebee-1.2.3",
		ExitCode:   2,
		Components: []model.Component{
			{Ecosystem: "npm", Name: "left-pad", Version: "1.3.0", SourceFile: "package-lock.json", Confidence: 0.99},
			{Ecosystem: "pypi", Name: "requests", Version: "2.31.0", SourceFile: "requirements.txt", Confidence: 1.0},
		},
		Findings: []model.Finding{
			{
				CatalogID: "MAL-2026-104", Severity: model.SeverityCritical, Class: model.ClassConfirmedMalicious,
				Ecosystem: "npm", Name: "evil-pkg", Version: "6.6.6", SourceFile: "package-lock.json",
				EvidenceType: "exact-version-match", Confidence: 1.0, Suppressed: false,
			},
			{
				CatalogID: "CVE-2026-9", Severity: model.SeverityMedium, Class: model.ClassVulnerable,
				Ecosystem: "pypi", Name: "requests", Version: "2.31.0", SourceFile: "requirements.txt",
				EvidenceType: "exact-version-match", Confidence: 0.8, Suppressed: true,
			},
		},
	}
}

func TestMigrationIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "guardian.db")

	s1, err := Open(path)
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	if err := s1.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}

	// Re-opening an existing DB must not fail and must leave user_version intact.
	s2, err := Open(path)
	if err != nil {
		t.Fatalf("second Open: %v", err)
	}
	defer s2.Close()

	var uv int
	if err := s2.db.QueryRow("PRAGMA user_version").Scan(&uv); err != nil {
		t.Fatalf("read user_version: %v", err)
	}
	if uv != schemaVersion {
		t.Fatalf("user_version = %d, want %d", uv, schemaVersion)
	}

	// A round-trip after reopen confirms the schema survived.
	ctx := context.Background()
	if _, err := s2.SaveRun(ctx, sampleRun()); err != nil {
		t.Fatalf("SaveRun after reopen: %v", err)
	}
}

func TestSaveRunRoundTrip(t *testing.T) {
	s := tempStore(t)
	ctx := context.Background()

	in := sampleRun()
	id, err := s.SaveRun(ctx, in)
	if err != nil {
		t.Fatalf("SaveRun: %v", err)
	}
	if id <= 0 {
		t.Fatalf("SaveRun returned non-positive id %d", id)
	}

	tests := []struct {
		name string
		load func() (*model.ScanRun, error)
	}{
		{"GetRun", func() (*model.ScanRun, error) { return s.GetRun(ctx, id) }},
		{"LatestRun", func() (*model.ScanRun, error) { return s.LatestRun(ctx) }},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.load()
			if err != nil {
				t.Fatalf("load: %v", err)
			}
			if got == nil {
				t.Fatal("load returned nil run")
			}
			if got.ID != id {
				t.Errorf("ID = %d, want %d", got.ID, id)
			}
			if !got.StartedAt.Equal(in.StartedAt) {
				t.Errorf("StartedAt = %v, want %v", got.StartedAt, in.StartedAt)
			}
			if !got.FinishedAt.Equal(in.FinishedAt) {
				t.Errorf("FinishedAt = %v, want %v", got.FinishedAt, in.FinishedAt)
			}
			if got.Profile != in.Profile {
				t.Errorf("Profile = %q, want %q", got.Profile, in.Profile)
			}
			if !reflect.DeepEqual(got.Roots, in.Roots) {
				t.Errorf("Roots = %v, want %v", got.Roots, in.Roots)
			}
			if got.CatalogVer != in.CatalogVer || got.Host != in.Host ||
				got.ScannerVer != in.ScannerVer || got.ExitCode != in.ExitCode {
				t.Errorf("metadata mismatch: %+v", got)
			}
			if !reflect.DeepEqual(got.Components, in.Components) {
				t.Errorf("Components = %+v, want %+v", got.Components, in.Components)
			}
			if !reflect.DeepEqual(got.Findings, in.Findings) {
				t.Errorf("Findings = %+v, want %+v", got.Findings, in.Findings)
			}
		})
	}
}

func TestLatestAndPreviousRun(t *testing.T) {
	s := tempStore(t)
	ctx := context.Background()

	if got, err := s.LatestRun(ctx); err != nil || got != nil {
		t.Fatalf("LatestRun on empty store = (%v, %v), want (nil, nil)", got, err)
	}

	r1 := sampleRun()
	r1.Host = "first"
	id1, err := s.SaveRun(ctx, r1)
	if err != nil {
		t.Fatalf("SaveRun r1: %v", err)
	}

	r2 := sampleRun()
	r2.Host = "second"
	r2.StartedAt = r1.StartedAt.Add(time.Hour)
	id2, err := s.SaveRun(ctx, r2)
	if err != nil {
		t.Fatalf("SaveRun r2: %v", err)
	}

	latest, err := s.LatestRun(ctx)
	if err != nil {
		t.Fatalf("LatestRun: %v", err)
	}
	if latest.ID != id2 || latest.Host != "second" {
		t.Errorf("LatestRun = id %d host %q, want id %d host second", latest.ID, latest.Host, id2)
	}

	prev, err := s.PreviousRun(ctx, id2)
	if err != nil {
		t.Fatalf("PreviousRun: %v", err)
	}
	if prev == nil || prev.ID != id1 || prev.Host != "first" {
		t.Errorf("PreviousRun(%d) = %+v, want id %d host first", id2, prev, id1)
	}

	// No run before the earliest.
	none, err := s.PreviousRun(ctx, id1)
	if err != nil {
		t.Fatalf("PreviousRun earliest: %v", err)
	}
	if none != nil {
		t.Errorf("PreviousRun(%d) = %+v, want nil", id1, none)
	}

	// GetRun on a missing id returns (nil, nil).
	missing, err := s.GetRun(ctx, 99999)
	if err != nil || missing != nil {
		t.Errorf("GetRun(missing) = (%v, %v), want (nil, nil)", missing, err)
	}
}

func TestRunsSince(t *testing.T) {
	s := tempStore(t)
	ctx := context.Background()

	base := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 3; i++ {
		r := sampleRun()
		r.StartedAt = base.AddDate(0, 0, i)
		r.FinishedAt = r.StartedAt.Add(time.Second)
		if _, err := s.SaveRun(ctx, r); err != nil {
			t.Fatalf("SaveRun %d: %v", i, err)
		}
	}

	since := base.AddDate(0, 0, 1) // includes day 1 and day 2
	runs, err := s.RunsSince(ctx, since)
	if err != nil {
		t.Fatalf("RunsSince: %v", err)
	}
	if len(runs) != 2 {
		t.Fatalf("RunsSince returned %d runs, want 2", len(runs))
	}
	// Metadata-only: children must be empty, ordered oldest-first.
	if !runs[0].StartedAt.Before(runs[1].StartedAt) {
		t.Errorf("runs not ordered oldest-first: %v then %v", runs[0].StartedAt, runs[1].StartedAt)
	}
	if len(runs[0].Components) != 0 || len(runs[0].Findings) != 0 {
		t.Errorf("RunsSince should not populate children, got %d comps %d finds",
			len(runs[0].Components), len(runs[0].Findings))
	}
}

func TestSuppressionLifecycle(t *testing.T) {
	s := tempStore(t)
	ctx := context.Background()

	now := time.Now()
	future := now.Add(24 * time.Hour)
	past := now.Add(-24 * time.Hour)

	neverID, err := s.AddSuppression(ctx, Suppression{
		Ecosystem: "npm", Name: "a", VersionRange: "*", Reason: "permanent",
	})
	if err != nil {
		t.Fatalf("AddSuppression never: %v", err)
	}

	activeID, err := s.AddSuppression(ctx, Suppression{
		Ecosystem: "npm", Name: "b", VersionRange: "1.x", Reason: "temp", ExpiresAt: &future,
	})
	if err != nil {
		t.Fatalf("AddSuppression active: %v", err)
	}

	expiredID, err := s.AddSuppression(ctx, Suppression{
		Ecosystem: "npm", Name: "c", VersionRange: "2.x", Reason: "stale", ExpiresAt: &past,
	})
	if err != nil {
		t.Fatalf("AddSuppression expired: %v", err)
	}

	active, err := s.ActiveSuppressions(ctx)
	if err != nil {
		t.Fatalf("ActiveSuppressions: %v", err)
	}
	gotIDs := map[int64]bool{}
	for _, a := range active {
		gotIDs[a.ID] = true
	}
	if !gotIDs[neverID] || !gotIDs[activeID] || gotIDs[expiredID] {
		t.Errorf("active set = %v, want never(%d)+active(%d), not expired(%d)",
			gotIDs, neverID, activeID, expiredID)
	}

	// Verify round-trip of fields incl. nil expiry.
	for _, a := range active {
		if a.ID == neverID && a.ExpiresAt != nil {
			t.Errorf("never-expiring suppression has ExpiresAt %v", a.ExpiresAt)
		}
		if a.ID == activeID {
			if a.ExpiresAt == nil {
				t.Errorf("active suppression missing ExpiresAt")
			} else if !a.ExpiresAt.Equal(future.UTC()) {
				t.Errorf("active suppression ExpiresAt = %v, want %v", a.ExpiresAt, future.UTC())
			}
		}
	}

	deleted, err := s.PruneExpiredSuppressions(ctx)
	if err != nil {
		t.Fatalf("PruneExpiredSuppressions: %v", err)
	}
	if deleted != 1 {
		t.Errorf("PruneExpiredSuppressions deleted %d, want 1", deleted)
	}

	// After prune, active set is unchanged and the expired row is gone.
	after, err := s.ActiveSuppressions(ctx)
	if err != nil {
		t.Fatalf("ActiveSuppressions after prune: %v", err)
	}
	if len(after) != 2 {
		t.Errorf("active after prune = %d, want 2", len(after))
	}
}

func TestPruneComponents(t *testing.T) {
	s := tempStore(t)
	ctx := context.Background()

	oldRun := sampleRun()
	oldRun.StartedAt = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	oldRun.FinishedAt = oldRun.StartedAt.Add(time.Second)
	oldID, err := s.SaveRun(ctx, oldRun)
	if err != nil {
		t.Fatalf("SaveRun old: %v", err)
	}

	newRun := sampleRun()
	newRun.StartedAt = time.Date(2026, 5, 24, 0, 0, 0, 0, time.UTC)
	newRun.FinishedAt = newRun.StartedAt.Add(time.Second)
	newID, err := s.SaveRun(ctx, newRun)
	if err != nil {
		t.Fatalf("SaveRun new: %v", err)
	}

	cutoff := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	deleted, err := s.PruneComponents(ctx, cutoff)
	if err != nil {
		t.Fatalf("PruneComponents: %v", err)
	}
	if deleted != int64(len(oldRun.Components)) {
		t.Errorf("deleted %d components, want %d", deleted, len(oldRun.Components))
	}

	// Old run keeps findings but loses components.
	old, err := s.GetRun(ctx, oldID)
	if err != nil {
		t.Fatalf("GetRun old: %v", err)
	}
	if len(old.Components) != 0 {
		t.Errorf("old run components = %d, want 0", len(old.Components))
	}
	if len(old.Findings) != len(oldRun.Findings) {
		t.Errorf("old run findings = %d, want %d (findings must be retained)",
			len(old.Findings), len(oldRun.Findings))
	}

	// New run is untouched.
	fresh, err := s.GetRun(ctx, newID)
	if err != nil {
		t.Fatalf("GetRun new: %v", err)
	}
	if len(fresh.Components) != len(newRun.Components) {
		t.Errorf("new run components = %d, want %d", len(fresh.Components), len(newRun.Components))
	}
}
