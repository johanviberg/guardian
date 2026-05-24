package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/johanviberg/guardian/internal/config"
	"github.com/johanviberg/guardian/internal/model"
)

// defaultDaemonInterval is used when the baseline schedule is unset/zero.
const defaultDaemonInterval = 30 * time.Minute

func newRunCmd() *cobra.Command {
	var noFetch bool

	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run the scheduling daemon",
		Long: "Runs baseline scans on the configured schedule interval (default 30m),\n" +
			"dispatching notifications on new critical/malicious findings. Stops cleanly\n" +
			"on SIGINT/SIGTERM.\n\n" +
			"NOTE: lockfile-watch (triggering a project scan on dependency change) is a\n" +
			"planned v1.1 feature and is not yet implemented; v1 uses a simple timer only.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			cfg, err := config.Load()
			if err != nil {
				return err
			}
			if err := cfg.Validate(); err != nil {
				return err
			}

			interval := scheduleInterval(cfg)
			fmt.Fprintf(os.Stderr, "guardian: daemon started; baseline scan every %s\n", interval)

			// Run once immediately, then on each tick.
			runOnce := func() {
				if err := daemonScan(ctx, cfg, noFetch); err != nil {
					fmt.Fprintf(os.Stderr, "guardian: scan error: %v\n", err)
				}
			}
			runOnce()

			ticker := time.NewTicker(interval)
			defer ticker.Stop()

			for {
				select {
				case <-ctx.Done():
					fmt.Fprintln(os.Stderr, "guardian: shutting down")
					return nil
				case <-ticker.C:
					runOnce()
				}
			}
		},
	}

	cmd.Flags().BoolVar(&noFetch, "no-fetch", false, "do not fetch the catalog; use the cached copy")
	return cmd
}

// scheduleInterval reads the baseline scan cadence from config, falling back to
// the daemon default when unset or non-positive.
func scheduleInterval(cfg *config.Config) time.Duration {
	mins := cfg.Schedule[string(model.ProfileBaseline)]
	if mins <= 0 {
		return defaultDaemonInterval
	}
	return time.Duration(mins) * time.Minute
}

// daemonScan runs one pipeline iteration and dispatches notifications for new
// findings. It always notifies (daemon mode) per the design.
func daemonScan(ctx context.Context, cfg *config.Config, noFetch bool) error {
	f := scanFlags{
		roots:   cfg.ScanRoots,
		noFetch: noFetch,
		notify:  true,
	}
	outcome, err := runScanPipeline(ctx, cfg, model.ProfileBaseline, f, os.Stderr)
	if err != nil {
		return err
	}
	dispatchNotifications(ctx, cfg, outcome.diff, os.Stderr)
	fmt.Fprintf(os.Stderr, "guardian: scan complete — %s\n", outcome.diff.Summarize("last run"))
	return nil
}
