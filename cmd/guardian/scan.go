package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/rmxventures/guardian/internal/model"
)

func newScanCmd() *cobra.Command {
	var (
		roots        []string
		catalogPath  string
		findingsOnly bool
		asJSON       bool
		doNotify     bool
		noFetch      bool
	)

	cmd := &cobra.Command{
		Use:       "scan [baseline|project|deep]",
		Short:     "Run a one-shot exposure scan",
		Long:      "Runs the full scan pipeline: ensure catalog, scan, classify, persist, diff, report.\nExit code: 0 clean, 1 non-critical findings, 2 confirmed-malicious/critical.",
		Args:      cobra.MaximumNArgs(1),
		ValidArgs: []string{"baseline", "project", "deep"},
		RunE: func(cmd *cobra.Command, args []string) error {
			profile := model.ProfileBaseline
			if len(args) == 1 {
				profile = model.Profile(args[0])
				switch profile {
				case model.ProfileBaseline, model.ProfileProject, model.ProfileDeep:
				default:
					return fmt.Errorf("unknown profile %q (want: baseline, project, deep)", args[0])
				}
			}

			ctx := cmd.Context()
			cfg, err := loadConfig(roots)
			if err != nil {
				return err
			}

			f := scanFlags{
				roots:        cfg.ScanRoots,
				catalogPath:  catalogPath,
				findingsOnly: findingsOnly,
				json:         asJSON,
				notify:       doNotify,
				noFetch:      noFetch,
			}

			outcome, err := runScanPipeline(ctx, cfg, profile, f, os.Stderr)
			if err != nil {
				return err
			}

			if err := renderScanOutcome(os.Stdout, outcome, asJSON); err != nil {
				return err
			}

			if doNotify {
				dispatchNotifications(ctx, cfg, outcome.diff, os.Stderr)
			}

			// Translate the policy exit code into the explicit exit scheme.
			if outcome.exitCode != 0 {
				return withCode(outcome.exitCode, nil)
			}
			return nil
		},
	}

	cmd.Flags().StringArrayVar(&roots, "root", nil, "scan root (repeatable); overrides configured roots")
	cmd.Flags().StringVar(&catalogPath, "catalog", "", "use this catalog file/dir instead of the fetched one")
	cmd.Flags().BoolVar(&findingsOnly, "findings-only", false, "emit only findings, skip inventory components")
	cmd.Flags().BoolVar(&asJSON, "json", false, "emit the stable JSON envelope")
	cmd.Flags().BoolVar(&doNotify, "notify", false, "dispatch notifications for new findings")
	cmd.Flags().BoolVar(&noFetch, "no-fetch", false, "do not fetch the catalog; use the cached copy")
	return cmd
}
