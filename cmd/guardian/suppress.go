package main

import (
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/johanviberg/guardian/internal/config"
	"github.com/johanviberg/guardian/internal/report"
	"github.com/johanviberg/guardian/internal/store"
)

func newSuppressCmd() *cobra.Command {
	var (
		reason string
		until  string
		asJSON bool
	)

	cmd := &cobra.Command{
		Use:   "suppress <ecosystem> <name> <version>",
		Short: "Suppress a finding, optionally with an expiry",
		Long:  "Adds a suppression matching (ecosystem, name, version). Use \"*\" for version to\nmatch any version. Suppressed findings are stored but excluded from exit-code\nescalation and notifications.",
		Args:  cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
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

			sup := store.Suppression{
				Ecosystem:    args[0],
				Name:         args[1],
				VersionRange: args[2],
				Reason:       reason,
				CreatedAt:    time.Now(),
			}
			if until != "" {
				dur, perr := parseExpiry(until)
				if perr != nil {
					return perr
				}
				exp := time.Now().Add(dur)
				sup.ExpiresAt = &exp
			}

			id, err := st.AddSuppression(ctx, sup)
			if err != nil {
				return err
			}

			if asJSON {
				return report.WriteJSON(os.Stdout, "suppress", map[string]any{
					"id":            id,
					"ecosystem":     sup.Ecosystem,
					"name":          sup.Name,
					"version_range": sup.VersionRange,
					"reason":        sup.Reason,
					"expires_at":    sup.ExpiresAt,
				})
			}
			if sup.ExpiresAt != nil {
				cmd.Printf("suppression #%d added for %s:%s@%s until %s\n",
					id, sup.Ecosystem, sup.Name, sup.VersionRange, sup.ExpiresAt.UTC().Format(time.RFC3339))
			} else {
				cmd.Printf("suppression #%d added for %s:%s@%s (no expiry)\n",
					id, sup.Ecosystem, sup.Name, sup.VersionRange)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&reason, "reason", "", "why this finding is suppressed")
	cmd.Flags().StringVar(&until, "until", "", "expiry duration: Go durations (e.g. 168h, 1h30m) plus day/week units (e.g. 7d, 2w)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "emit the stable JSON envelope")
	return cmd
}
