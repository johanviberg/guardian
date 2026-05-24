package config

import (
	"fmt"
	"os"
	"strings"
	"time"
)

// splitList splits an OS path-list-separated string into trimmed entries.
func splitList(s string) []string {
	sep := string(os.PathListSeparator)
	parts := strings.Split(s, sep)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// Flag-override keys understood by ApplyFlagOverrides. cmd/ maps its parsed
// flags to these keys; this keeps the cmd wiring (out of scope here) decoupled
// from the config struct's internal layout.
const (
	FlagScanRoots              = "scan_roots"               // []string or string list
	FlagCatalogSourceURL       = "catalog.source_url"       // string
	FlagCatalogFreshnessTTL    = "catalog.freshness_ttl"    // time.Duration or string
	FlagCatalogCacheDir        = "catalog.cache_dir"        // string
	FlagNotifyChannels         = "notify.channels"          // []string
	FlagNotifyWebhookURL       = "notify.webhook_url"       // string
	FlagNotifyMinSeverity      = "notify.min_severity"      // string
	FlagNotifyQuietHoursStart  = "notify.quiet_hours.start" // string
	FlagNotifyQuietHoursEnd    = "notify.quiet_hours.end"   // string
	FlagRetentionComponentDays = "retention.component_days" // int
	FlagDBPath                 = "db_path"                  // string
	FlagStateDir               = "state_dir"                // string
)

// ApplyFlagOverrides layers command-line flag values (highest precedence) onto
// cfg. Keys absent from overrides leave cfg untouched, so cmd/ only needs to
// populate the keys whose flags were actually set by the user.
//
// Values are accepted in the natural Go types a flag library produces
// (string, []string, int, bool, time.Duration); strings are coerced where a
// stronger type is expected. An unknown key or an unconvertible value returns
// an error rather than being silently dropped.
func ApplyFlagOverrides(cfg *Config, overrides map[string]any) error {
	if cfg == nil {
		return fmt.Errorf("config: ApplyFlagOverrides on nil config")
	}
	for key, raw := range overrides {
		if err := applyOne(cfg, key, raw); err != nil {
			return err
		}
	}
	return nil
}

func applyOne(cfg *Config, key string, raw any) error {
	switch key {
	case FlagScanRoots:
		v, err := asStringSlice(key, raw)
		if err != nil {
			return err
		}
		cfg.SetScanRoots(v)
	case FlagCatalogSourceURL:
		v, err := asString(key, raw)
		if err != nil {
			return err
		}
		cfg.Catalog.SourceURL = v
	case FlagCatalogFreshnessTTL:
		d, err := asDuration(key, raw)
		if err != nil {
			return err
		}
		cfg.Catalog.FreshnessTTL = d
	case FlagCatalogCacheDir:
		v, err := asString(key, raw)
		if err != nil {
			return err
		}
		cfg.Catalog.CacheDir = v
	case FlagNotifyChannels:
		v, err := asStringSlice(key, raw)
		if err != nil {
			return err
		}
		cfg.Notify.Channels = v
	case FlagNotifyWebhookURL:
		v, err := asString(key, raw)
		if err != nil {
			return err
		}
		cfg.Notify.WebhookURL = v
	case FlagNotifyMinSeverity:
		v, err := asString(key, raw)
		if err != nil {
			return err
		}
		cfg.Notify.MinSeverity = v
	case FlagNotifyQuietHoursStart:
		v, err := asString(key, raw)
		if err != nil {
			return err
		}
		cfg.Notify.QuietHours.Start = v
	case FlagNotifyQuietHoursEnd:
		v, err := asString(key, raw)
		if err != nil {
			return err
		}
		cfg.Notify.QuietHours.End = v
	case FlagRetentionComponentDays:
		v, err := asInt(key, raw)
		if err != nil {
			return err
		}
		cfg.Retention.ComponentDays = v
	case FlagDBPath:
		v, err := asString(key, raw)
		if err != nil {
			return err
		}
		cfg.DBPath = v
	case FlagStateDir:
		v, err := asString(key, raw)
		if err != nil {
			return err
		}
		cfg.StateDir = v
	default:
		return fmt.Errorf("config: unknown flag override %q", key)
	}
	return nil
}

// ----- individual setters (alternative to ApplyFlagOverrides for cmd/) -----

// SetScanRoots replaces the configured scan roots.
func (c *Config) SetScanRoots(roots []string) { c.ScanRoots = append([]string(nil), roots...) }

// SetCatalogSourceURL overrides the catalog source URL.
func (c *Config) SetCatalogSourceURL(u string) { c.Catalog.SourceURL = u }

// SetCatalogFreshnessTTL overrides the catalog freshness TTL.
func (c *Config) SetCatalogFreshnessTTL(d time.Duration) { c.Catalog.FreshnessTTL = d }

// SetNotifyChannels overrides the enabled notification channels.
func (c *Config) SetNotifyChannels(ch []string) { c.Notify.Channels = append([]string(nil), ch...) }

// SetNotifyWebhookURL overrides the webhook URL.
func (c *Config) SetNotifyWebhookURL(u string) { c.Notify.WebhookURL = u }

// SetDBPath overrides the database path.
func (c *Config) SetDBPath(p string) { c.DBPath = p }

// SetStateDir overrides the state directory.
func (c *Config) SetStateDir(p string) { c.StateDir = p }

// ----- coercion helpers -----

func asString(key string, raw any) (string, error) {
	s, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("config: flag %q: want string, got %T", key, raw)
	}
	return s, nil
}

func asInt(key string, raw any) (int, error) {
	switch v := raw.(type) {
	case int:
		return v, nil
	case int64:
		return int(v), nil
	case string:
		var n int
		if _, err := fmt.Sscanf(v, "%d", &n); err != nil {
			return 0, fmt.Errorf("config: flag %q: %w", key, err)
		}
		return n, nil
	default:
		return 0, fmt.Errorf("config: flag %q: want int, got %T", key, raw)
	}
}

func asDuration(key string, raw any) (time.Duration, error) {
	switch v := raw.(type) {
	case time.Duration:
		return v, nil
	case string:
		d, err := time.ParseDuration(v)
		if err != nil {
			return 0, fmt.Errorf("config: flag %q: %w", key, err)
		}
		return d, nil
	default:
		return 0, fmt.Errorf("config: flag %q: want duration, got %T", key, raw)
	}
}

func asStringSlice(key string, raw any) ([]string, error) {
	switch v := raw.(type) {
	case []string:
		return append([]string(nil), v...), nil
	case string:
		return splitCSV(v), nil
	default:
		return nil, fmt.Errorf("config: flag %q: want []string, got %T", key, raw)
	}
}
