// Package config loads guardian's runtime configuration from a layered set of
// sources. Precedence, lowest to highest, is:
//
//	defaults  <  YAML file  <  environment (GUARDIAN_*)  <  flags
//
// This package implements defaults, the YAML file overlay, and the environment
// overlay. Flag layering is left to cmd/ via ApplyFlagOverrides and the
// individual setters, so the CLI can decide how its flags map onto fields.
//
// All filesystem locations resolve to OS-appropriate directories using
// os.UserConfigDir / os.UserCacheDir and an XDG-style state directory.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

// Defaults that are independent of the host environment.
const (
	// DefaultCatalogSourceURL is the upstream Bumblebee threat-intel catalog.
	DefaultCatalogSourceURL = "https://raw.githubusercontent.com/perplexityai/bumblebee/main/threat_intel/catalog.json"
	// DefaultFreshnessTTL is how long a fetched catalog is considered fresh.
	DefaultFreshnessTTL = 24 * time.Hour
	// DefaultRetentionComponentDays is the inventory retention window.
	DefaultRetentionComponentDays = 30
	// DefaultMinSeverity gates notifications at and above this severity.
	DefaultMinSeverity = "critical"
	// configDirName is the per-app subdirectory used under every base dir.
	appDirName = "guardian"
	// configFileName is the YAML config file name.
	configFileName = "guardian.yaml"
)

// CatalogConfig configures exposure-catalog fetching and caching.
type CatalogConfig struct {
	SourceURL    string        `json:"source_url" yaml:"source_url"`
	FreshnessTTL time.Duration `json:"freshness_ttl" yaml:"freshness_ttl"`
	CacheDir     string        `json:"cache_dir" yaml:"cache_dir"`
}

// QuietHours is an inclusive local-time window during which notifications are
// suppressed. Empty Start and End disables the window. Times are "HH:MM".
type QuietHours struct {
	Start string `json:"start" yaml:"start"`
	End   string `json:"end" yaml:"end"`
}

// Enabled reports whether a quiet-hours window is configured.
func (q QuietHours) Enabled() bool { return q.Start != "" && q.End != "" }

// NotifyConfig configures notification fan-out.
type NotifyConfig struct {
	Channels    []string   `json:"channels" yaml:"channels"`         // terminal, desktop, webhook
	WebhookURL  string     `json:"webhook_url" yaml:"webhook_url"`   //
	MinSeverity string     `json:"min_severity" yaml:"min_severity"` // critical|high|medium|low|info
	QuietHours  QuietHours `json:"quiet_hours" yaml:"quiet_hours"`   //
}

// RetentionConfig configures history pruning.
type RetentionConfig struct {
	ComponentDays int `json:"component_days" yaml:"component_days"`
}

// Config is guardian's fully merged runtime configuration.
type Config struct {
	// ScanRoots are explicit roots scanned in addition to profile defaults.
	ScanRoots []string `json:"scan_roots" yaml:"scan_roots"`
	// Schedule maps a profile name to its scan interval in minutes (0 = off).
	Schedule map[string]int `json:"schedule" yaml:"schedule"`

	Catalog   CatalogConfig   `json:"catalog" yaml:"catalog"`
	Notify    NotifyConfig    `json:"notify" yaml:"notify"`
	Retention RetentionConfig `json:"retention" yaml:"retention"`

	// Filesystem locations (resolved to OS-appropriate defaults).
	DBPath   string `json:"db_path" yaml:"db_path"`
	StateDir string `json:"state_dir" yaml:"state_dir"`
}

// Defaults returns a Config populated with sensible defaults, including
// OS-appropriate filesystem paths resolved from the current environment.
func Defaults() *Config {
	stateDir := defaultStateDir()
	cacheDir := defaultCacheDir()
	return &Config{
		ScanRoots: nil,
		Schedule: map[string]int{
			string("baseline"): 60,
			string("project"):  0,
			string("deep"):     0,
		},
		Catalog: CatalogConfig{
			SourceURL:    DefaultCatalogSourceURL,
			FreshnessTTL: DefaultFreshnessTTL,
			CacheDir:     filepath.Join(cacheDir, "catalog"),
		},
		Notify: NotifyConfig{
			Channels:    []string{"terminal"},
			MinSeverity: DefaultMinSeverity,
		},
		Retention: RetentionConfig{
			ComponentDays: DefaultRetentionComponentDays,
		},
		StateDir: stateDir,
		DBPath:   filepath.Join(stateDir, "guardian.db"),
	}
}

// Load builds the effective configuration by layering, in order:
// defaults, the YAML file (if present), then GUARDIAN_* environment variables.
// Flags are layered on afterwards by the caller via ApplyFlagOverrides.
func Load() (*Config, error) {
	cfg := Defaults()

	path, err := ConfigFilePath()
	if err != nil {
		return nil, err
	}
	if path != "" {
		if err := overlayFile(cfg, path); err != nil {
			return nil, err
		}
	}

	if err := overlayEnv(cfg, os.Environ()); err != nil {
		return nil, err
	}
	return cfg, nil
}

// ConfigFilePath returns the path guardian reads its YAML config from, honoring
// XDG_CONFIG_HOME and falling back to os.UserConfigDir. It returns an empty
// path with no error when no config file exists.
func ConfigFilePath() (string, error) {
	dir, err := configBaseDir()
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, appDirName, configFileName)
	if _, statErr := os.Stat(path); statErr != nil {
		if os.IsNotExist(statErr) {
			return "", nil
		}
		return "", statErr
	}
	return path, nil
}

// overlayFile parses a YAML config file and overlays its values onto cfg.
func overlayFile(cfg *Config, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("config: read %s: %w", path, err)
	}
	doc, err := parseYAML(string(data))
	if err != nil {
		return fmt.Errorf("config: parse %s: %w", path, err)
	}
	if err := applyYAML(cfg, doc); err != nil {
		return fmt.Errorf("config: apply %s: %w", path, err)
	}
	return nil
}

// Validate checks that the merged config is internally consistent and usable.
func (c *Config) Validate() error {
	if c == nil {
		return fmt.Errorf("config: nil config")
	}
	if c.Catalog.SourceURL == "" {
		return fmt.Errorf("config: catalog.source_url must not be empty")
	}
	if !strings.HasPrefix(c.Catalog.SourceURL, "http://") &&
		!strings.HasPrefix(c.Catalog.SourceURL, "https://") {
		return fmt.Errorf("config: catalog.source_url must be an http(s) URL, got %q", c.Catalog.SourceURL)
	}
	if c.Catalog.FreshnessTTL <= 0 {
		return fmt.Errorf("config: catalog.freshness_ttl must be positive, got %s", c.Catalog.FreshnessTTL)
	}
	if c.Retention.ComponentDays < 0 {
		return fmt.Errorf("config: retention.component_days must not be negative, got %d", c.Retention.ComponentDays)
	}
	if c.DBPath == "" {
		return fmt.Errorf("config: db_path must not be empty")
	}
	if c.StateDir == "" {
		return fmt.Errorf("config: state_dir must not be empty")
	}
	if !validSeverity(c.Notify.MinSeverity) {
		return fmt.Errorf("config: notify.min_severity %q is not a valid severity", c.Notify.MinSeverity)
	}
	for _, ch := range c.Notify.Channels {
		if !validChannel(ch) {
			return fmt.Errorf("config: notify.channels has unknown channel %q", ch)
		}
	}
	if c.Notify.QuietHours.Enabled() {
		if err := validClock(c.Notify.QuietHours.Start); err != nil {
			return fmt.Errorf("config: notify.quiet_hours.start: %w", err)
		}
		if err := validClock(c.Notify.QuietHours.End); err != nil {
			return fmt.Errorf("config: notify.quiet_hours.end: %w", err)
		}
	}
	for profile, mins := range c.Schedule {
		if mins < 0 {
			return fmt.Errorf("config: schedule[%s] must not be negative, got %d", profile, mins)
		}
	}
	return nil
}

func validSeverity(s string) bool {
	switch s {
	case "critical", "high", "medium", "low", "info":
		return true
	}
	return false
}

func validChannel(s string) bool {
	switch s {
	case "terminal", "desktop", "webhook":
		return true
	}
	return false
}

func validClock(s string) error {
	if _, err := time.Parse("15:04", s); err != nil {
		return fmt.Errorf("invalid HH:MM time %q", s)
	}
	return nil
}

// ----- OS-appropriate path resolution -----

// configBaseDir returns the base directory config lives under, honoring
// XDG_CONFIG_HOME and falling back to os.UserConfigDir.
func configBaseDir() (string, error) {
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
		return x, nil
	}
	return os.UserConfigDir()
}

// defaultCacheDir resolves the app cache directory (parent of catalog cache).
func defaultCacheDir() string {
	if x := os.Getenv("XDG_CACHE_HOME"); x != "" {
		return filepath.Join(x, appDirName)
	}
	if dir, err := os.UserCacheDir(); err == nil {
		return filepath.Join(dir, appDirName)
	}
	return filepath.Join(homeDir(), ".cache", appDirName)
}

// defaultStateDir resolves the app state directory (DB, runs), XDG_STATE_HOME
// with an OS-appropriate fallback.
func defaultStateDir() string {
	if x := os.Getenv("XDG_STATE_HOME"); x != "" {
		return filepath.Join(x, appDirName)
	}
	switch runtime.GOOS {
	case "windows", "darwin":
		// No standard state dir on these platforms; reuse the config base.
		if dir, err := os.UserConfigDir(); err == nil {
			return filepath.Join(dir, appDirName, "state")
		}
	}
	return filepath.Join(homeDir(), ".local", "state", appDirName)
}

func homeDir() string {
	if h, err := os.UserHomeDir(); err == nil && h != "" {
		return h
	}
	if h := os.Getenv("HOME"); h != "" {
		return h
	}
	return "."
}

// Effective returns a deterministic, human-readable rendering of the merged
// config for `guardian doctor`. It is also the basis of String.
func (c *Config) Effective() string {
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format, args...) }

	w("scan_roots:\n")
	if len(c.ScanRoots) == 0 {
		w("  (none; profile defaults only)\n")
	}
	for _, r := range c.ScanRoots {
		w("  - %s\n", r)
	}

	w("schedule (minutes, 0 = off):\n")
	for _, p := range sortedKeys(c.Schedule) {
		w("  %s: %d\n", p, c.Schedule[p])
	}

	w("catalog:\n")
	w("  source_url:    %s\n", c.Catalog.SourceURL)
	w("  freshness_ttl: %s\n", c.Catalog.FreshnessTTL)
	w("  cache_dir:     %s\n", c.Catalog.CacheDir)

	w("notify:\n")
	w("  channels:      %s\n", strings.Join(c.Notify.Channels, ", "))
	w("  webhook_url:   %s\n", redact(c.Notify.WebhookURL))
	w("  min_severity:  %s\n", c.Notify.MinSeverity)
	if c.Notify.QuietHours.Enabled() {
		w("  quiet_hours:   %s-%s\n", c.Notify.QuietHours.Start, c.Notify.QuietHours.End)
	} else {
		w("  quiet_hours:   (disabled)\n")
	}

	w("retention:\n")
	w("  component_days: %d\n", c.Retention.ComponentDays)

	w("paths:\n")
	w("  state_dir: %s\n", c.StateDir)
	w("  db_path:   %s\n", c.DBPath)

	return b.String()
}

// String implements fmt.Stringer with the effective rendering.
func (c *Config) String() string { return c.Effective() }

func sortedKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// redact hides a credential-bearing URL when set, without leaking it.
func redact(s string) string {
	if s == "" {
		return "(unset)"
	}
	return "(set)"
}
