package main

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/johanviberg/guardian/internal/catalog"
	"github.com/johanviberg/guardian/internal/config"
	"github.com/johanviberg/guardian/internal/report"
)

func newCatalogCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "catalog",
		Short: "Fetch and inspect exposure catalogs",
		Args:  cobra.NoArgs,
	}
	cmd.AddCommand(newCatalogUpdateCmd(), newCatalogListCmd(), newCatalogShowCmd())
	return cmd
}

func newCatalogUpdateCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "update",
		Short: "Fetch the latest catalog and refresh the cache",
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
			mgr, err := newCatalogManager(cfg, false)
			if err != nil {
				return err
			}
			path, version, err := mgr.Ensure(ctx)
			if err != nil {
				return err
			}
			if asJSON {
				return report.WriteJSON(os.Stdout, "catalog.update", map[string]any{
					"version": version,
					"path":    path,
				})
			}
			cmd.Printf("catalog %s cached at %s\n", version, path)
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "emit the stable JSON envelope")
	return cmd
}

func newCatalogListCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List cached catalog metadata",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			meta, ok := readCatalogMeta(cfg)
			version, _, stale := catalogFreshness(ctx, cfg)
			if asJSON {
				payload := map[string]any{"cached": ok}
				if ok {
					payload["meta"] = meta
					payload["stale"] = stale
				}
				return report.WriteJSON(os.Stdout, "catalog.list", payload)
			}
			if !ok {
				cmd.Println("no catalog cached. Run `guardian catalog update`.")
				return nil
			}
			cmd.Printf("version:     %s\n", version)
			cmd.Printf("fetched_at:  %s\n", meta.FetchedAt.UTC().Format("2006-01-02 15:04:05 MST"))
			cmd.Printf("entries:     %d\n", meta.EntryCount)
			cmd.Printf("fresh:       %t\n", !stale)
			cmd.Printf("source_url:  %s\n", meta.SourceURL)
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "emit the stable JSON envelope")
	return cmd
}

func newCatalogShowCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "show",
		Short: "Show full cached catalog provenance",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			meta, ok := readCatalogMeta(cfg)
			if asJSON {
				return report.WriteJSON(os.Stdout, "catalog.show", map[string]any{
					"cached": ok,
					"meta":   meta,
				})
			}
			if !ok {
				cmd.Println("no catalog cached. Run `guardian catalog update`.")
				return nil
			}
			cmd.Printf("version:     %s\n", meta.Version)
			cmd.Printf("fetched_at:  %s\n", meta.FetchedAt.UTC().Format("2006-01-02 15:04:05 MST"))
			cmd.Printf("sha256:      %s\n", meta.SHA256)
			cmd.Printf("entries:     %d\n", meta.EntryCount)
			cmd.Printf("source_url:  %s\n", meta.SourceURL)
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "emit the stable JSON envelope")
	return cmd
}

// readCatalogMeta reads the cached catalog metadata sidecar directly. ok is
// false when no cached metadata exists.
func readCatalogMeta(cfg *config.Config) (catalog.Meta, bool) {
	path := filepath.Join(cfg.Catalog.CacheDir, "catalog.meta.json")
	// #nosec G304 -- path is derived from the user's own configured catalog cache
	// dir; reading the metadata sidecar for a read-only JSON decode is intended.
	data, err := os.ReadFile(path)
	if err != nil {
		return catalog.Meta{}, false
	}
	var meta catalog.Meta
	if err := json.Unmarshal(data, &meta); err != nil {
		return catalog.Meta{}, false
	}
	return meta, true
}
