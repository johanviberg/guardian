package main

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/spf13/cobra"

	"github.com/johanviberg/guardian/internal/config"
	"github.com/johanviberg/guardian/internal/diff"
	"github.com/johanviberg/guardian/internal/model"
	"github.com/johanviberg/guardian/internal/report"
	"github.com/johanviberg/guardian/internal/store"
)

func newDiffCmd() *cobra.Command {
	var (
		since  string
		asJSON bool
	)

	cmd := &cobra.Command{
		Use:   "diff",
		Short: "Diff the latest scan against a prior run",
		Long:  "Compares the latest run against the previous one, or against the run at or just\nbefore --since (a run id or a duration like 24h).",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			if err := cfg.Validate(); err != nil {
				return err
			}

			st, err := openStore(cfg)
			if err != nil {
				return err
			}
			defer st.Close()

			latest, err := st.LatestRun(ctx)
			if err != nil {
				return err
			}
			if latest == nil {
				return fmt.Errorf("no scans recorded yet; run `guardian scan` first")
			}

			prev, err := resolvePrevious(ctx, st, latest, since)
			if err != nil {
				return err
			}

			d := diff.Compare(prev, latest)
			view := report.DiffView{
				New:        d.New,
				Resolved:   d.Resolved,
				Persisting: d.Persisting,
			}
			if asJSON {
				return report.WriteJSON(os.Stdout, "diff", view)
			}
			return report.Renderer{}.RenderDiff(os.Stdout, view)
		},
	}

	cmd.Flags().StringVar(&since, "since", "", "compare against run id or duration (e.g. 7, 24h)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "emit the stable JSON envelope")
	return cmd
}

// resolvePrevious selects the baseline run to diff against. With no --since it
// is the run immediately before latest. With --since as an integer it is that
// run id; as a duration it is the most recent run started at or before
// now-duration. Returns (nil, nil) when there is no suitable prior run (every
// finding then shows as New).
func resolvePrevious(ctx context.Context, st *store.Store, latest *model.ScanRun, since string) (*model.ScanRun, error) {
	if since == "" {
		return st.PreviousRun(ctx, latest.ID)
	}

	if id, err := strconv.ParseInt(since, 10, 64); err == nil {
		run, gErr := st.GetRun(ctx, id)
		if gErr != nil {
			return nil, gErr
		}
		if run == nil {
			return nil, fmt.Errorf("no run with id %d", id)
		}
		return run, nil
	}

	if dur, err := time.ParseDuration(since); err == nil {
		cutoff := time.Now().Add(-dur)
		return runAtOrBefore(ctx, st, latest, cutoff)
	}

	return nil, fmt.Errorf("invalid --since %q: want a run id or a duration like 24h", since)
}

// runAtOrBefore returns the most recent run (other than latest) started at or
// before cutoff. It walks runs since cutoff and, if none qualify, falls back to
// the immediate predecessor.
func runAtOrBefore(ctx context.Context, st *store.Store, latest *model.ScanRun, cutoff time.Time) (*model.ScanRun, error) {
	runs, err := st.RunsSince(ctx, time.Time{})
	if err != nil {
		return nil, err
	}
	var best *model.ScanRun
	for i := range runs {
		r := runs[i]
		if r.ID == latest.ID {
			continue
		}
		if !r.StartedAt.After(cutoff) {
			if best == nil || r.StartedAt.After(best.StartedAt) {
				rr := r
				best = &rr
			}
		}
	}
	if best == nil {
		return st.PreviousRun(ctx, latest.ID)
	}
	// Re-load with children populated (RunsSince returns metadata only).
	return st.GetRun(ctx, best.ID)
}
