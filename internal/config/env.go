package config

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Environment variable names recognised by overlayEnv. All are prefixed
// GUARDIAN_ and take precedence over the YAML file but below flags.
const (
	EnvScanRoots              = "GUARDIAN_SCAN_ROOTS"               // os.PathListSeparator-joined list
	EnvCatalogSourceURL       = "GUARDIAN_CATALOG_SOURCE_URL"       //
	EnvCatalogFreshnessTTL    = "GUARDIAN_CATALOG_FRESHNESS_TTL"    // Go duration, e.g. 24h
	EnvCatalogCacheDir        = "GUARDIAN_CATALOG_CACHE_DIR"        //
	EnvCatalogVerify          = "GUARDIAN_CATALOG_VERIFY"           // off|warn|require
	EnvCatalogPublicKey       = "GUARDIAN_CATALOG_PUBLIC_KEY"       // path or inline minisign key
	EnvNotifyChannels         = "GUARDIAN_NOTIFY_CHANNELS"          // comma-separated
	EnvNotifyWebhookURL       = "GUARDIAN_NOTIFY_WEBHOOK_URL"       //
	EnvNotifyMinSeverity      = "GUARDIAN_NOTIFY_MIN_SEVERITY"      //
	EnvNotifyQuietHoursStart  = "GUARDIAN_NOTIFY_QUIET_HOURS_START" // HH:MM
	EnvNotifyQuietHoursEnd    = "GUARDIAN_NOTIFY_QUIET_HOURS_END"   // HH:MM
	EnvRetentionComponentDays = "GUARDIAN_RETENTION_COMPONENT_DAYS"
	EnvDBPath                 = "GUARDIAN_DB_PATH"
	EnvStateDir               = "GUARDIAN_STATE_DIR"
)

// EnvSchedulePrefix introduces per-profile schedule overrides, e.g.
// GUARDIAN_SCHEDULE_BASELINE=30 sets the baseline interval to 30 minutes.
const EnvSchedulePrefix = "GUARDIAN_SCHEDULE_"

// overlayEnv applies GUARDIAN_* variables (given as "KEY=VALUE" lines, like
// os.Environ) onto cfg. Unset variables leave cfg untouched.
func overlayEnv(cfg *Config, environ []string) error {
	env := map[string]string{}
	for _, kv := range environ {
		i := strings.IndexByte(kv, '=')
		if i < 0 {
			continue
		}
		env[kv[:i]] = kv[i+1:]
	}

	if v, ok := env[EnvScanRoots]; ok {
		cfg.ScanRoots = splitList(v)
	}
	if v, ok := env[EnvCatalogSourceURL]; ok {
		cfg.Catalog.SourceURL = v
	}
	if v, ok := env[EnvCatalogFreshnessTTL]; ok {
		d, err := time.ParseDuration(v)
		if err != nil {
			return fmt.Errorf("config: %s: %w", EnvCatalogFreshnessTTL, err)
		}
		cfg.Catalog.FreshnessTTL = d
	}
	if v, ok := env[EnvCatalogCacheDir]; ok {
		cfg.Catalog.CacheDir = v
	}
	if v, ok := env[EnvCatalogVerify]; ok {
		cfg.Catalog.Verify = v
	}
	if v, ok := env[EnvCatalogPublicKey]; ok {
		cfg.Catalog.PublicKey = v
	}
	if v, ok := env[EnvNotifyChannels]; ok {
		cfg.Notify.Channels = splitCSV(v)
	}
	if v, ok := env[EnvNotifyWebhookURL]; ok {
		cfg.Notify.WebhookURL = v
	}
	if v, ok := env[EnvNotifyMinSeverity]; ok {
		cfg.Notify.MinSeverity = v
	}
	if v, ok := env[EnvNotifyQuietHoursStart]; ok {
		cfg.Notify.QuietHours.Start = v
	}
	if v, ok := env[EnvNotifyQuietHoursEnd]; ok {
		cfg.Notify.QuietHours.End = v
	}
	if v, ok := env[EnvRetentionComponentDays]; ok {
		n, err := strconv.Atoi(v)
		if err != nil {
			return fmt.Errorf("config: %s: %w", EnvRetentionComponentDays, err)
		}
		cfg.Retention.ComponentDays = n
	}
	if v, ok := env[EnvDBPath]; ok {
		cfg.DBPath = v
	}
	if v, ok := env[EnvStateDir]; ok {
		cfg.StateDir = v
	}

	// Per-profile schedule overrides: GUARDIAN_SCHEDULE_<PROFILE>=<minutes>.
	for key, val := range env {
		if !strings.HasPrefix(key, EnvSchedulePrefix) {
			continue
		}
		profile := strings.ToLower(strings.TrimPrefix(key, EnvSchedulePrefix))
		if profile == "" {
			continue
		}
		n, err := strconv.Atoi(val)
		if err != nil {
			return fmt.Errorf("config: %s: %w", key, err)
		}
		if cfg.Schedule == nil {
			cfg.Schedule = map[string]int{}
		}
		cfg.Schedule[profile] = n
	}
	return nil
}

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
