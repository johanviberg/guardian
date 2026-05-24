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
			fs, err := newFeedSet(cfg, false, os.Stderr)
			if err != nil {
				return err
			}
			path, version, err := fs.Ensure(ctx)
			if err != nil {
				return err
			}
			if asJSON {
				fm, _ := fs.LoadFeedMeta()
				return report.WriteJSON(os.Stdout, "catalog.update", map[string]any{
					"version": version,
					"path":    path,
					"sources": fm.Sources,
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

			// Try the new feed.meta.json first, fall back to catalog.meta.json.
			version, fetchedAt, stale := catalogFreshness(ctx, cfg)

			// Try to read the rich FeedMeta.
			fm, hasFeedMeta := readFeedMeta(cfg)

			if asJSON {
				if hasFeedMeta {
					payload := map[string]any{
						"cached":  true,
						"version": version,
						"stale":   stale,
						"sources": fm.Sources,
					}
					return report.WriteJSON(os.Stdout, "catalog.list", payload)
				}
				meta, ok := readCatalogMeta(cfg)
				payload := map[string]any{"cached": ok}
				if ok {
					payload["meta"] = meta
					payload["stale"] = stale
				}
				return report.WriteJSON(os.Stdout, "catalog.list", payload)
			}

			if version == "" {
				cmd.Println("no catalog cached. Run `guardian catalog update`.")
				return nil
			}
			cmd.Printf("version:     %s\n", version)
			if !fetchedAt.IsZero() {
				cmd.Printf("fetched_at:  %s\n", fetchedAt.UTC().Format("2006-01-02 15:04:05 MST"))
			}
			cmd.Printf("fresh:       %t\n", !stale)
			if hasFeedMeta {
				cmd.Printf("entry_count: %d\n", fm.EntryCount)
				cmd.Printf("sources (%d):\n", len(fm.Sources))
				for _, s := range fm.Sources {
					status := "ok"
					if s.Stale {
						status = "stale"
					}
					if s.Skipped {
						status = "skipped"
					}
					cmd.Printf("  [%s] version=%s status=%s\n", s.Name, s.Version, status)
				}
			}
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

			// Try rich FeedMeta first.
			fm, hasFeedMeta := readFeedMeta(cfg)
			if asJSON {
				if hasFeedMeta {
					return report.WriteJSON(os.Stdout, "catalog.show", map[string]any{
						"cached": true,
						"meta":   fm,
					})
				}
				meta, ok := readCatalogMeta(cfg)
				return report.WriteJSON(os.Stdout, "catalog.show", map[string]any{
					"cached": ok,
					"meta":   meta,
				})
			}

			if hasFeedMeta {
				cmd.Printf("version:     %s\n", fm.Version)
				cmd.Printf("fetched_at:  %s\n", fm.FetchedAt.UTC().Format("2006-01-02 15:04:05 MST"))
				cmd.Printf("sha256:      %s\n", fm.SHA256)
				cmd.Printf("entries:     %d\n", fm.EntryCount)
				cmd.Printf("sources (%d):\n", len(fm.Sources))
				for _, s := range fm.Sources {
					cmd.Printf("  [%s]\n", s.Name)
					cmd.Printf("    url:        %s\n", s.URL)
					cmd.Printf("    version:    %s\n", s.Version)
					cmd.Printf("    fetched_at: %s\n", s.FetchedAt.UTC().Format("2006-01-02 15:04:05 MST"))
					cmd.Printf("    sha256:     %s\n", s.SHA256)
					if s.Stale {
						cmd.Printf("    status:     stale\n")
					}
					if s.Skipped {
						cmd.Printf("    status:     skipped\n")
					}
				}
				if len(fm.Warnings) > 0 {
					cmd.Printf("warnings (%d):\n", len(fm.Warnings))
					for _, w := range fm.Warnings {
						cmd.Printf("  - %s\n", w)
					}
				}
				return nil
			}

			meta, ok := readCatalogMeta(cfg)
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

// readFeedMeta reads the rich FeedMeta sidecar (multi-source). ok is false when
// absent or unreadable.
func readFeedMeta(cfg *config.Config) (catalog.FeedMeta, bool) {
	path := filepath.Join(cfg.Catalog.CacheDir, "feed.meta.json")
	// #nosec G304 -- path is derived from the user's configured catalog cache dir;
	// reading the metadata sidecar for a read-only JSON decode is intended.
	data, err := os.ReadFile(path)
	if err != nil {
		return catalog.FeedMeta{}, false
	}
	var fm catalog.FeedMeta
	if err := json.Unmarshal(data, &fm); err != nil {
		return catalog.FeedMeta{}, false
	}
	return fm, true
}

// readCatalogMeta reads the legacy single-source catalog.meta.json sidecar.
// ok is false when absent or unreadable.
func readCatalogMeta(cfg *config.Config) (catalog.Meta, bool) {
	path := filepath.Join(cfg.Catalog.CacheDir, "catalog.meta.json")
	// #nosec G304 -- path is derived from the user's configured catalog cache dir;
	// reading the metadata sidecar for a read-only JSON decode is intended.
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
