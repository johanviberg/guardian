package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/rmxventures/guardian/internal/config"
	"github.com/rmxventures/guardian/internal/service"
)

// serviceLabel is the reverse-DNS identifier for the installed unit.
const serviceLabel = "io.guardian.agent"

func newServiceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "service",
		Short: "Install or remove a native scheduling unit",
		Args:  cobra.NoArgs,
	}
	cmd.AddCommand(newServiceInstallCmd(), newServiceUninstallCmd())
	return cmd
}

// serviceConfig builds a service.Config from the loaded guardian config. In
// daemon mode Args is ["run"]; with --cron it is ["scan","baseline"] for
// repeated one-shot scans.
func serviceConfig(cfg *config.Config, cron bool) (service.Config, error) {
	exe, err := os.Executable()
	if err != nil {
		return service.Config{}, fmt.Errorf("resolve executable path: %w", err)
	}
	args := []string{"run"}
	if cron {
		args = []string{"scan", "baseline"}
	}
	interval := int(scheduleInterval(cfg).Minutes())
	if interval <= 0 {
		interval = int(defaultDaemonInterval.Minutes())
	}
	return service.Config{
		Label:           serviceLabel,
		ExecPath:        exe,
		Args:            args,
		IntervalMinutes: interval,
		Description:     "guardian supply-chain exposure scanner",
	}, nil
}

func newServiceInstallCmd() *cobra.Command {
	var cron bool
	cmd := &cobra.Command{
		Use:   "install",
		Short: "Install the scheduling unit (launchd/systemd/schtasks, or --cron)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			if err := cfg.Validate(); err != nil {
				return err
			}
			sc, err := serviceConfig(cfg, cron)
			if err != nil {
				return err
			}

			mgr := service.New()
			if cron {
				mgr = service.CronManager()
			}

			if err := mgr.Install(sc); err != nil {
				return err
			}
			if path := mgr.UnitPath(sc); path != "" {
				cmd.Printf("installed %s -> %s (every %d min)\n", sc.Label, path, sc.IntervalMinutes)
			} else {
				cmd.Printf("installed %s (every %d min)\n", sc.Label, sc.IntervalMinutes)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&cron, "cron", false, "use a crontab entry instead of the native scheduler")
	return cmd
}

func newServiceUninstallCmd() *cobra.Command {
	var cron bool
	cmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Remove the installed scheduling unit",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			mgr := service.New()
			if cron {
				mgr = service.CronManager()
			}
			if err := mgr.Uninstall(serviceLabel); err != nil {
				return err
			}
			cmd.Printf("uninstalled %s\n", serviceLabel)
			return nil
		},
	}
	cmd.Flags().BoolVar(&cron, "cron", false, "remove the crontab entry instead of the native unit")
	return cmd
}
