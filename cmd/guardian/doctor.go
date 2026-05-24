package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/rmxventures/guardian/internal/config"
	"github.com/rmxventures/guardian/internal/report"
	"github.com/rmxventures/guardian/internal/scanner"
)

// checkResult is one diagnostic check outcome. A failing critical check makes
// `guardian doctor` exit non-zero; a warning does not.
type checkResult struct {
	Name     string `json:"name"`
	OK       bool   `json:"ok"`
	Critical bool   `json:"critical"`
	Detail   string `json:"detail"`
}

func (c checkResult) failedCritical() bool { return !c.OK && c.Critical }

func newDoctorCmd() *cobra.Command {
	var asJSON bool

	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Run environment and configuration health checks",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			checks, cfg := runDoctorChecks(ctx)

			if asJSON {
				payload := map[string]any{"checks": checks}
				if cfg != nil {
					payload["effective_config"] = cfg.Effective()
				}
				if err := report.WriteJSON(os.Stdout, "doctor", payload); err != nil {
					return err
				}
			} else {
				for _, c := range checks {
					mark := "ok"
					if !c.OK {
						if c.Critical {
							mark = "FAIL"
						} else {
							mark = "warn"
						}
					}
					fmt.Fprintf(os.Stdout, "[%-4s] %s\n", mark, c.Name)
					if c.Detail != "" {
						fmt.Fprintf(os.Stdout, "        %s\n", c.Detail)
					}
				}
				if cfg != nil {
					fmt.Fprintln(os.Stdout, "\neffective config:")
					fmt.Fprint(os.Stdout, indent(cfg.Effective()))
				}
			}

			for _, c := range checks {
				if c.failedCritical() {
					return withCode(2, nil)
				}
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&asJSON, "json", false, "emit the stable JSON envelope")
	return cmd
}

// runDoctorChecks performs all health checks and returns them plus the loaded
// config (nil if config loading itself failed).
func runDoctorChecks(ctx context.Context) ([]checkResult, *config.Config) {
	var checks []checkResult

	// 1. Scanner self-test (critical).
	sc := scanner.NewVendoredScanner()
	stCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := sc.SelfTest(stCtx); err != nil {
		checks = append(checks, checkResult{Name: "scanner self-test", OK: false, Critical: true, Detail: err.Error()})
	} else {
		checks = append(checks, checkResult{Name: "scanner self-test", OK: true, Detail: "engine " + sc.Version()})
	}

	// 2. Config load + validate (critical).
	cfg, err := config.Load()
	if err != nil {
		checks = append(checks, checkResult{Name: "config load", OK: false, Critical: true, Detail: err.Error()})
		return checks, nil
	}
	if err := cfg.Validate(); err != nil {
		checks = append(checks, checkResult{Name: "config validate", OK: false, Critical: true, Detail: err.Error()})
		return checks, cfg
	}
	checks = append(checks, checkResult{Name: "config valid", OK: true})

	// 3. State dir writable (critical).
	if err := checkWritableDir(cfg.StateDir); err != nil {
		checks = append(checks, checkResult{Name: "state dir writable", OK: false, Critical: true, Detail: err.Error()})
	} else {
		checks = append(checks, checkResult{Name: "state dir writable", OK: true, Detail: cfg.StateDir})
	}

	// 4. DB openable (critical).
	if dbStore, err := openStore(cfg); err != nil {
		checks = append(checks, checkResult{Name: "database openable", OK: false, Critical: true, Detail: err.Error()})
	} else {
		_ = dbStore.Close()
		checks = append(checks, checkResult{Name: "database openable", OK: true, Detail: cfg.DBPath})
	}

	// 5. Catalog freshness (warning only: a fresh machine has no catalog yet).
	version, fetchedAt, stale := catalogFreshness(ctx, cfg)
	switch {
	case version == "":
		checks = append(checks, checkResult{Name: "catalog cached", OK: false, Critical: false, Detail: "no catalog cached; run `guardian catalog update`"})
	case stale:
		checks = append(checks, checkResult{Name: "catalog fresh", OK: false, Critical: false,
			Detail: fmt.Sprintf("stale (fetched %s); run `guardian catalog update`", fetchedAt.UTC().Format(time.RFC3339))})
	default:
		checks = append(checks, checkResult{Name: "catalog fresh", OK: true, Detail: version})
	}

	return checks, cfg
}

// checkWritableDir ensures dir exists (creating it) and is writable by creating
// and removing a probe file.
func checkWritableDir(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	probe := filepath.Join(dir, ".guardian-doctor-probe")
	if err := os.WriteFile(probe, []byte("ok"), 0o600); err != nil {
		return fmt.Errorf("write probe in %s: %w", dir, err)
	}
	_ = os.Remove(probe)
	return nil
}

// indent prefixes every non-empty line of s with two spaces.
func indent(s string) string {
	var out []byte
	lineStart := true
	for i := 0; i < len(s); i++ {
		if lineStart && s[i] != '\n' {
			out = append(out, ' ', ' ')
		}
		out = append(out, s[i])
		lineStart = s[i] == '\n'
	}
	return string(out)
}
