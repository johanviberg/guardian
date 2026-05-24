package main

import (
	"context"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/johanviberg/guardian/internal/config"
	"github.com/johanviberg/guardian/internal/report"
)

func newStatusCmd() *cobra.Command {
	var asJSON bool

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show host, catalog freshness, last scan, and current exposures",
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

			// Catalog freshness (no network).
			catVer, _, stale := catalogFreshness(ctx, cfg)

			st, err := openStore(cfg)
			if err != nil {
				return err
			}
			defer st.Close()

			latest, err := st.LatestRun(ctx)
			if err != nil {
				return err
			}

			view := report.StatusView{
				CatalogVersion: catVer,
				CatalogFresh:   !stale,
			}
			if latest != nil {
				view.Host = latest.Host
				view.LastScanAt = latest.FinishedAt
				active := actionable(latest.Findings)
				view.Findings = active
				view.Counts = report.CountFindings(active)
				if catVer == "" {
					view.CatalogVersion = latest.CatalogVer
				}
			} else {
				host, _ := os.Hostname()
				view.Host = host
			}

			if asJSON {
				return report.WriteJSON(os.Stdout, "status", view)
			}
			return report.Renderer{}.RenderStatus(os.Stdout, view)
		},
	}

	cmd.Flags().BoolVar(&asJSON, "json", false, "emit the stable JSON envelope")
	return cmd
}

// catalogFreshness reports the cached catalog version, fetch time, and staleness
// without any network access. A missing catalog reports version "" and stale.
func catalogFreshness(ctx context.Context, cfg *config.Config) (version string, fetchedAt time.Time, stale bool) {
	mgr, err := newCatalogManager(cfg, true)
	if err != nil {
		return "", time.Time{}, true
	}
	v, fa, st, err := mgr.Freshness(ctx)
	if err != nil {
		return "", time.Time{}, true
	}
	return v, fa, st
}
