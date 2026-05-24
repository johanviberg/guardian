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
	// DefaultCatalogSourceURL is the upstream Bumblebee threat-intel feed. It is
	// the GitHub Contents API listing for the threat_intel/ directory (a set of
	// per-advisory catalogs that the catalog manager downloads and merges), NOT a
	// single catalog.json — upstream publishes no such bundle. Keep this in sync
	// with catalog.DefaultSourceURL.
	DefaultCatalogSourceURL = "https://api.github.com/repos/perplexityai/bumblebee/contents/threat_intel?ref=main"
	// DefaultFreshnessTTL is how long a fetched catalog is considered fresh.
	DefaultFreshnessTTL = 24 * time.Hour
	// DefaultRetentionComponentDays is the inventory retention window.
	DefaultRetentionComponentDays = 30
	// DefaultMinSeverity gates notifications at and above this severity.
	DefaultMinSeverity = "critical"
	// DefaultEnrichCacheTTL is how long a cached OSV vuln detail is reused.
	DefaultEnrichCacheTTL = 24 * time.Hour
	// configDirName is the per-app subdirectory used under every base dir.
	appDirName = "guardian"
	// configFileName is the YAML config file name.
	configFileName = "guardian.yaml"
)

// Catalog signature-verification modes.
const (
	// VerifyOff disables signature verification entirely (default; the default
	// upstream feed is unsigned).
	VerifyOff = "off"
	// VerifyWarn verifies when a signature is available and warns (but proceeds)
	// on a missing or invalid signature.
	VerifyWarn = "warn"
	// VerifyRequire demands a valid signature from the trusted key on every
	// catalog file; a missing or invalid signature aborts the update.
	VerifyRequire = "require"
)

// CatalogSource is a single self-contained catalog feed. When multiple sources
// are configured, their entries are merged by union with conflict resolution
// (union versions, highest severity).
type CatalogSource struct {
	// Name is a human-readable stable identifier for this source. If empty,
	// EffectiveSources assigns "source-N".
	Name string `json:"name" yaml:"name"`
	// URL is the HTTPS URL to fetch from. Same semantics as CatalogConfig.SourceURL.
	URL string `json:"url" yaml:"url"`
	// Verify selects minisign verification for this source: "off", "warn", "require".
	// Defaults to "off" when empty.
	Verify string `json:"verify" yaml:"verify"`
	// PublicKey is the trusted minisign public key for this source (path or inline).
	// Required when Verify == "require".
	PublicKey string `json:"public_key" yaml:"public_key"`
}

// CatalogConfig configures exposure-catalog fetching and caching.
type CatalogConfig struct {
	// SourceURL / Verify / PublicKey are the BACK-COMPAT single-source shorthand.
	// They are used when Sources is empty (EffectiveSources synthesises one source
	// from them). When Sources is non-empty these fields are ignored for fetch
	// purposes but SourceURL still feeds Validate's URL check.
	SourceURL    string        `json:"source_url" yaml:"source_url"`
	FreshnessTTL time.Duration `json:"freshness_ttl" yaml:"freshness_ttl"`
	CacheDir     string        `json:"cache_dir" yaml:"cache_dir"`

	// Verify selects minisign signature verification for the back-compat single
	// source: "off" (default), "warn", or "require".
	Verify string `json:"verify" yaml:"verify"`

	// PublicKey is the trusted minisign public key for the back-compat single
	// source (path to a .pub file OR inline key text).
	PublicKey string `json:"public_key" yaml:"public_key"`

	// Sources is the multi-source list. When non-empty it takes precedence over
	// SourceURL/Verify/PublicKey for fetch purposes (back-compat shorthand becomes
	// a no-op). Multi-source is configured via YAML only; there are no per-source
	// env vars.
	Sources []CatalogSource `json:"sources" yaml:"sources"`
}

// EffectiveSources returns the list of sources to fetch. If Sources is non-empty
// it is returned (with empty Verify defaulted to "off" and unnamed entries named
// "source-N"). Otherwise a single source is synthesised from the back-compat
// SourceURL/Verify/PublicKey fields with name "default".
func (cc CatalogConfig) EffectiveSources() []CatalogSource {
	if len(cc.Sources) > 0 {
		out := make([]CatalogSource, len(cc.Sources))
		for i, s := range cc.Sources {
			out[i] = s
			if out[i].Name == "" {
				out[i].Name = fmt.Sprintf("source-%d", i+1)
			}
			if out[i].Verify == "" {
				out[i].Verify = VerifyOff
			}
		}
		return out
	}
	return []CatalogSource{{
		Name:      "default",
		URL:       cc.SourceURL,
		Verify:    cc.Verify,
		PublicKey: cc.PublicKey,
	}}
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

// EnrichConfig configures optional vulnerability enrichment. Enrichment is
// OPT-IN and OFF BY DEFAULT; when enabled, supported components are queried
// against external advisory databases (currently OSV at api.osv.dev). Results
// are INFORMATIONAL by default and only escalate the exit code when FailOn is
// set to a severity threshold.
type EnrichConfig struct {
	// Enabled turns enrichment on. Default false.
	Enabled bool `json:"enabled" yaml:"enabled"`
	// Sources selects enrichment backends. Default ["osv"].
	Sources []string `json:"sources" yaml:"sources"`
	// FailOn is the minimum severity at which an enrichment finding escalates
	// the exit code to 1. Empty ("") means enrichment never gates (informational
	// only). Valid values: "" or a severity.
	FailOn string `json:"fail_on" yaml:"fail_on"`
	// CacheTTL is how long cached advisory details are reused. Default 24h.
	CacheTTL time.Duration `json:"cache_ttl" yaml:"cache_ttl"`
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
	Enrich    EnrichConfig    `json:"enrich" yaml:"enrich"`
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
			Verify:       VerifyOff,
		},
		Notify: NotifyConfig{
			Channels:    []string{"terminal"},
			MinSeverity: DefaultMinSeverity,
		},
		Enrich: EnrichConfig{
			Enabled:  false,
			Sources:  []string{"osv"},
			FailOn:   "",
			CacheTTL: DefaultEnrichCacheTTL,
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

// overlayFile parses a YAML config file via yaml.v3 and overlays its values
// onto cfg. Only keys present in the file touch cfg; absent keys keep their
// current (default) values. Unknown top-level keys are rejected so typos in
// guardian.yaml surface as an error rather than being silently ignored.
func overlayFile(cfg *Config, path string) error {
	// #nosec G304 -- path is the user-supplied guardian config file location;
	// reading it for a read-only YAML overlay decode is the function of this API.
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("config: read %s: %w", path, err)
	}
	if err := applyYAML(cfg, data); err != nil {
		return fmt.Errorf("config: %s: %w", path, err)
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
	if !validVerifyMode(c.Catalog.Verify) {
		return fmt.Errorf("config: catalog.verify %q must be one of %q, %q, %q",
			c.Catalog.Verify, VerifyOff, VerifyWarn, VerifyRequire)
	}
	if c.Catalog.Verify == VerifyRequire && c.Catalog.PublicKey == "" {
		return fmt.Errorf("config: catalog.verify is %q but catalog.public_key is not set", VerifyRequire)
	}
	// Validate each explicitly configured source.
	for i, src := range c.Catalog.Sources {
		name := src.Name
		if name == "" {
			name = fmt.Sprintf("source-%d", i+1)
		}
		if src.URL == "" {
			return fmt.Errorf("config: catalog.sources[%s]: url must not be empty", name)
		}
		if !strings.HasPrefix(src.URL, "http://") && !strings.HasPrefix(src.URL, "https://") {
			return fmt.Errorf("config: catalog.sources[%s]: url must be http(s), got %q", name, src.URL)
		}
		verify := src.Verify
		if verify == "" {
			verify = VerifyOff
		}
		if !validVerifyMode(verify) {
			return fmt.Errorf("config: catalog.sources[%s]: verify %q must be one of %q, %q, %q",
				name, verify, VerifyOff, VerifyWarn, VerifyRequire)
		}
		if verify == VerifyRequire && src.PublicKey == "" {
			return fmt.Errorf("config: catalog.sources[%s]: verify is %q but public_key is not set", name, VerifyRequire)
		}
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
	if c.Enrich.FailOn != "" && !validSeverity(c.Enrich.FailOn) {
		return fmt.Errorf("config: enrich.fail_on %q must be empty or a valid severity", c.Enrich.FailOn)
	}
	if c.Enrich.CacheTTL < 0 {
		return fmt.Errorf("config: enrich.cache_ttl must not be negative, got %s", c.Enrich.CacheTTL)
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

func validVerifyMode(s string) bool {
	switch s {
	case VerifyOff, VerifyWarn, VerifyRequire:
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
	w("  freshness_ttl: %s\n", c.Catalog.FreshnessTTL)
	w("  cache_dir:     %s\n", c.Catalog.CacheDir)
	srcs := c.Catalog.EffectiveSources()
	if len(c.Catalog.Sources) == 0 {
		// Back-compat single-source shorthand.
		w("  source_url:    %s\n", c.Catalog.SourceURL)
		w("  verify:        %s\n", c.Catalog.Verify)
		w("  public_key:    %s\n", redact(c.Catalog.PublicKey))
	} else {
		w("  sources (%d):\n", len(srcs))
		for _, s := range srcs {
			w("    [%s] url=%s verify=%s public_key=%s\n", s.Name, s.URL, s.Verify, redact(s.PublicKey))
		}
	}

	w("notify:\n")
	w("  channels:      %s\n", strings.Join(c.Notify.Channels, ", "))
	w("  webhook_url:   %s\n", redact(c.Notify.WebhookURL))
	w("  min_severity:  %s\n", c.Notify.MinSeverity)
	if c.Notify.QuietHours.Enabled() {
		w("  quiet_hours:   %s-%s\n", c.Notify.QuietHours.Start, c.Notify.QuietHours.End)
	} else {
		w("  quiet_hours:   (disabled)\n")
	}

	w("enrich:\n")
	w("  enabled:   %t\n", c.Enrich.Enabled)
	w("  sources:   %s\n", strings.Join(c.Enrich.Sources, ", "))
	if c.Enrich.FailOn == "" {
		w("  fail_on:   (informational; never gates)\n")
	} else {
		w("  fail_on:   %s\n", c.Enrich.FailOn)
	}
	w("  cache_ttl: %s\n", c.Enrich.CacheTTL)

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
