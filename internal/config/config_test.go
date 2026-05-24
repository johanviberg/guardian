package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// isolateEnv clears all GUARDIAN_* and XDG_* / HOME vars for a clean baseline,
// then points HOME and XDG dirs at a temp directory.
func isolateEnv(t *testing.T) string {
	t.Helper()
	for _, kv := range os.Environ() {
		k := kv[:strings.IndexByte(kv, '=')]
		if strings.HasPrefix(k, "GUARDIAN_") || strings.HasPrefix(k, "XDG_") {
			t.Setenv(k, "")
			os.Unsetenv(k)
		}
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "config"))
	t.Setenv("XDG_CACHE_HOME", filepath.Join(home, "cache"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(home, "state"))
	return home
}

func writeConfig(t *testing.T, body string) {
	t.Helper()
	dir := filepath.Join(os.Getenv("XDG_CONFIG_HOME"), appDirName)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, configFileName), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestCatalogVerifyConfig(t *testing.T) {
	isolateEnv(t)

	// Default is off.
	if got := Defaults().Catalog.Verify; got != VerifyOff {
		t.Fatalf("default verify = %q, want %q", got, VerifyOff)
	}

	// Invalid mode rejected.
	c := Defaults()
	c.Catalog.Verify = "bogus"
	if err := c.Validate(); err == nil {
		t.Fatal("Validate accepted invalid verify mode")
	}

	// require without public_key rejected.
	c = Defaults()
	c.Catalog.Verify = VerifyRequire
	if err := c.Validate(); err == nil {
		t.Fatal("Validate accepted require without public_key")
	}

	// require with public_key accepted.
	c.Catalog.PublicKey = "/path/to/key.pub"
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate(require + key) = %v", err)
	}

	// warn is valid even without a key.
	c = Defaults()
	c.Catalog.Verify = VerifyWarn
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate(warn) = %v", err)
	}

	// Env overlay.
	t.Setenv("GUARDIAN_CATALOG_VERIFY", "require")
	t.Setenv("GUARDIAN_CATALOG_PUBLIC_KEY", "RWQinline")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Catalog.Verify != VerifyRequire || cfg.Catalog.PublicKey != "RWQinline" {
		t.Fatalf("env overlay: verify=%q key=%q", cfg.Catalog.Verify, cfg.Catalog.PublicKey)
	}
}

func TestCatalogVerifyYAML(t *testing.T) {
	isolateEnv(t)
	writeConfig(t, "catalog:\n  verify: warn\n  public_key: /etc/guardian/feed.pub\n")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Catalog.Verify != VerifyWarn {
		t.Fatalf("yaml verify = %q", cfg.Catalog.Verify)
	}
	if cfg.Catalog.PublicKey != "/etc/guardian/feed.pub" {
		t.Fatalf("yaml public_key = %q", cfg.Catalog.PublicKey)
	}
}

func TestEffectiveSources_BackCompat(t *testing.T) {
	isolateEnv(t)
	cfg := Defaults()
	// No Sources set: EffectiveSources returns one "default" source from SourceURL.
	srcs := cfg.Catalog.EffectiveSources()
	if len(srcs) != 1 {
		t.Fatalf("want 1 source, got %d", len(srcs))
	}
	if srcs[0].Name != "default" {
		t.Fatalf("name = %q, want default", srcs[0].Name)
	}
	if srcs[0].URL != cfg.Catalog.SourceURL {
		t.Fatalf("url = %q", srcs[0].URL)
	}
	if srcs[0].Verify != VerifyOff {
		t.Fatalf("verify = %q", srcs[0].Verify)
	}
}

func TestEffectiveSources_MultiSource(t *testing.T) {
	isolateEnv(t)
	cfg := Defaults()
	cfg.Catalog.Sources = []CatalogSource{
		{Name: "a", URL: "https://a.example.com/cat.json", Verify: VerifyOff},
		{Name: "b", URL: "https://b.example.com/listing", Verify: VerifyWarn, PublicKey: "/k.pub"},
		{URL: "https://c.example.com/cat.json"}, // unnamed — gets "source-3"
	}
	srcs := cfg.Catalog.EffectiveSources()
	if len(srcs) != 3 {
		t.Fatalf("want 3 sources, got %d", len(srcs))
	}
	if srcs[0].Name != "a" || srcs[1].Name != "b" {
		t.Fatalf("names = [%q %q]", srcs[0].Name, srcs[1].Name)
	}
	if srcs[2].Name != "source-3" {
		t.Fatalf("unnamed source name = %q, want source-3", srcs[2].Name)
	}
	// Empty verify defaults to off.
	if srcs[2].Verify != VerifyOff {
		t.Fatalf("unnamed source verify = %q, want off", srcs[2].Verify)
	}
}

func TestValidate_MultiSource(t *testing.T) {
	isolateEnv(t)
	base := Defaults()

	// Missing url rejected.
	c := *base
	c.Catalog.Sources = []CatalogSource{{Name: "x", Verify: VerifyOff}}
	if err := c.Validate(); err == nil {
		t.Fatal("want error for missing source url")
	}

	// Bad verify mode rejected.
	c = *base
	c.Catalog.Sources = []CatalogSource{{Name: "x", URL: "https://x.example.com/c.json", Verify: "bad"}}
	if err := c.Validate(); err == nil {
		t.Fatal("want error for bad source verify mode")
	}

	// require without key rejected.
	c = *base
	c.Catalog.Sources = []CatalogSource{{Name: "x", URL: "https://x.example.com/c.json", Verify: VerifyRequire}}
	if err := c.Validate(); err == nil {
		t.Fatal("want error for require without public_key")
	}

	// require with key accepted.
	c = *base
	c.Catalog.Sources = []CatalogSource{{Name: "x", URL: "https://x.example.com/c.json", Verify: VerifyRequire, PublicKey: "/k.pub"}}
	if err := c.Validate(); err != nil {
		t.Fatalf("require + key: %v", err)
	}

	// warn without key accepted.
	c = *base
	c.Catalog.Sources = []CatalogSource{{Name: "x", URL: "https://x.example.com/c.json", Verify: VerifyWarn}}
	if err := c.Validate(); err != nil {
		t.Fatalf("warn without key: %v", err)
	}
}

func TestMultiSourceYAML(t *testing.T) {
	isolateEnv(t)
	writeConfig(t, `catalog:
  sources:
    - name: upstream
      url: https://api.github.com/repos/perplexityai/bumblebee/contents/threat_intel?ref=main
      verify: off
    - name: internal
      url: https://internal.example.com/catalog.json
      verify: require
      public_key: /etc/guardian/internal.pub
`)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Catalog.Sources) != 2 {
		t.Fatalf("sources len = %d, want 2", len(cfg.Catalog.Sources))
	}
	if cfg.Catalog.Sources[0].Name != "upstream" {
		t.Fatalf("sources[0].name = %q", cfg.Catalog.Sources[0].Name)
	}
	if cfg.Catalog.Sources[1].Verify != VerifyRequire {
		t.Fatalf("sources[1].verify = %q", cfg.Catalog.Sources[1].Verify)
	}
	if cfg.Catalog.Sources[1].PublicKey != "/etc/guardian/internal.pub" {
		t.Fatalf("sources[1].public_key = %q", cfg.Catalog.Sources[1].PublicKey)
	}
	// EffectiveSources uses Sources since non-empty.
	srcs := cfg.Catalog.EffectiveSources()
	if len(srcs) != 2 || srcs[0].Name != "upstream" {
		t.Fatalf("EffectiveSources: %v", srcs)
	}
}

func TestDefaults(t *testing.T) {
	isolateEnv(t)
	cfg := Defaults()
	if cfg.Catalog.SourceURL != DefaultCatalogSourceURL {
		t.Errorf("source url = %q", cfg.Catalog.SourceURL)
	}
	if cfg.Catalog.FreshnessTTL != DefaultFreshnessTTL {
		t.Errorf("ttl = %s", cfg.Catalog.FreshnessTTL)
	}
	if cfg.Retention.ComponentDays != DefaultRetentionComponentDays {
		t.Errorf("retention = %d", cfg.Retention.ComponentDays)
	}
	if got := cfg.Schedule["baseline"]; got != 60 {
		t.Errorf("baseline schedule = %d", got)
	}
	if len(cfg.Notify.Channels) != 1 || cfg.Notify.Channels[0] != "terminal" {
		t.Errorf("channels = %v", cfg.Notify.Channels)
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("defaults should validate: %v", err)
	}
}

func TestLoadPrecedence_FileOverDefaults(t *testing.T) {
	isolateEnv(t)
	writeConfig(t, `
scan_roots:
  - /srv/app
  - /opt/tools
schedule:
  baseline: 30
  project: 15
catalog:
  source_url: https://example.com/catalog.json
  freshness_ttl: 6h
notify:
  channels: [terminal, webhook]
  webhook_url: https://hooks.example.com/x
  min_severity: high
  quiet_hours:
    start: "22:00"
    end: "07:00"
retention:
  component_days: 90
`)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.ScanRoots) != 2 || cfg.ScanRoots[0] != "/srv/app" {
		t.Errorf("scan roots = %v", cfg.ScanRoots)
	}
	if cfg.Schedule["baseline"] != 30 || cfg.Schedule["project"] != 15 {
		t.Errorf("schedule = %v", cfg.Schedule)
	}
	if cfg.Catalog.SourceURL != "https://example.com/catalog.json" {
		t.Errorf("source url = %q", cfg.Catalog.SourceURL)
	}
	if cfg.Catalog.FreshnessTTL != 6*time.Hour {
		t.Errorf("ttl = %s", cfg.Catalog.FreshnessTTL)
	}
	if cfg.Notify.MinSeverity != "high" {
		t.Errorf("min severity = %q", cfg.Notify.MinSeverity)
	}
	if cfg.Notify.WebhookURL != "https://hooks.example.com/x" {
		t.Errorf("webhook = %q", cfg.Notify.WebhookURL)
	}
	if !cfg.Notify.QuietHours.Enabled() || cfg.Notify.QuietHours.Start != "22:00" {
		t.Errorf("quiet hours = %+v", cfg.Notify.QuietHours)
	}
	if cfg.Retention.ComponentDays != 90 {
		t.Errorf("retention = %d", cfg.Retention.ComponentDays)
	}
}

func TestLoadPrecedence_EnvOverFile(t *testing.T) {
	isolateEnv(t)
	writeConfig(t, `
catalog:
  source_url: https://file.example.com/catalog.json
  freshness_ttl: 6h
notify:
  min_severity: high
retention:
  component_days: 90
`)
	t.Setenv("GUARDIAN_CATALOG_SOURCE_URL", "https://env.example.com/catalog.json")
	t.Setenv("GUARDIAN_CATALOG_FRESHNESS_TTL", "2h")
	t.Setenv("GUARDIAN_NOTIFY_MIN_SEVERITY", "critical")
	t.Setenv("GUARDIAN_RETENTION_COMPONENT_DAYS", "7")
	t.Setenv("GUARDIAN_SCHEDULE_BASELINE", "5")

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Catalog.SourceURL != "https://env.example.com/catalog.json" {
		t.Errorf("env should win: %q", cfg.Catalog.SourceURL)
	}
	if cfg.Catalog.FreshnessTTL != 2*time.Hour {
		t.Errorf("ttl = %s", cfg.Catalog.FreshnessTTL)
	}
	if cfg.Notify.MinSeverity != "critical" {
		t.Errorf("min severity = %q", cfg.Notify.MinSeverity)
	}
	if cfg.Retention.ComponentDays != 7 {
		t.Errorf("retention = %d", cfg.Retention.ComponentDays)
	}
	if cfg.Schedule["baseline"] != 5 {
		t.Errorf("schedule baseline = %d", cfg.Schedule["baseline"])
	}
}

func TestLoadPrecedence_ScanRootsEnvPathList(t *testing.T) {
	isolateEnv(t)
	val := strings.Join([]string{"/a", "/b"}, string(os.PathListSeparator))
	t.Setenv("GUARDIAN_SCAN_ROOTS", val)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.ScanRoots) != 2 || cfg.ScanRoots[1] != "/b" {
		t.Errorf("scan roots = %v", cfg.ScanRoots)
	}
}

func TestApplyFlagOverrides_HighestPrecedence(t *testing.T) {
	isolateEnv(t)
	t.Setenv("GUARDIAN_NOTIFY_MIN_SEVERITY", "high")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	err = ApplyFlagOverrides(cfg, map[string]any{
		FlagNotifyMinSeverity:      "low",
		FlagCatalogFreshnessTTL:    "12h",
		FlagScanRoots:              []string{"/x", "/y"},
		FlagRetentionComponentDays: 3,
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Notify.MinSeverity != "low" {
		t.Errorf("flag should win over env: %q", cfg.Notify.MinSeverity)
	}
	if cfg.Catalog.FreshnessTTL != 12*time.Hour {
		t.Errorf("ttl = %s", cfg.Catalog.FreshnessTTL)
	}
	if len(cfg.ScanRoots) != 2 || cfg.ScanRoots[0] != "/x" {
		t.Errorf("roots = %v", cfg.ScanRoots)
	}
	if cfg.Retention.ComponentDays != 3 {
		t.Errorf("retention = %d", cfg.Retention.ComponentDays)
	}
}

func TestApplyFlagOverrides_UnknownKey(t *testing.T) {
	cfg := Defaults()
	if err := ApplyFlagOverrides(cfg, map[string]any{"bogus": 1}); err == nil {
		t.Fatal("expected error for unknown key")
	}
}

func TestPathResolution_XDG(t *testing.T) {
	home := isolateEnv(t)
	cfg := Defaults()
	wantState := filepath.Join(home, "state", appDirName)
	if cfg.StateDir != wantState {
		t.Errorf("state dir = %q want %q", cfg.StateDir, wantState)
	}
	if cfg.DBPath != filepath.Join(wantState, "guardian.db") {
		t.Errorf("db path = %q", cfg.DBPath)
	}
	wantCache := filepath.Join(home, "cache", appDirName, "catalog")
	if cfg.Catalog.CacheDir != wantCache {
		t.Errorf("cache dir = %q want %q", cfg.Catalog.CacheDir, wantCache)
	}
}

func TestPathResolution_NoXDGState(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("home-relative state path not used on windows")
	}
	home := t.TempDir()
	for _, kv := range os.Environ() {
		k := kv[:strings.IndexByte(kv, '=')]
		if strings.HasPrefix(k, "XDG_") {
			os.Unsetenv(k)
		}
	}
	t.Setenv("HOME", home)
	os.Unsetenv("XDG_STATE_HOME")

	got := defaultStateDir()
	if runtime.GOOS == "linux" {
		want := filepath.Join(home, ".local", "state", appDirName)
		if got != want {
			t.Errorf("state dir = %q want %q", got, want)
		}
	}
}

func TestConfigFilePath_AbsentReturnsEmpty(t *testing.T) {
	isolateEnv(t)
	path, err := ConfigFilePath()
	if err != nil {
		t.Fatal(err)
	}
	if path != "" {
		t.Errorf("expected empty path for absent config, got %q", path)
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr bool
	}{
		{"defaults ok", func(*Config) {}, false},
		{"empty source url", func(c *Config) { c.Catalog.SourceURL = "" }, true},
		{"non-http url", func(c *Config) { c.Catalog.SourceURL = "ftp://x" }, true},
		{"zero ttl", func(c *Config) { c.Catalog.FreshnessTTL = 0 }, true},
		{"negative retention", func(c *Config) { c.Retention.ComponentDays = -1 }, true},
		{"empty db path", func(c *Config) { c.DBPath = "" }, true},
		{"empty state dir", func(c *Config) { c.StateDir = "" }, true},
		{"bad severity", func(c *Config) { c.Notify.MinSeverity = "nope" }, true},
		{"bad channel", func(c *Config) { c.Notify.Channels = []string{"carrier-pigeon"} }, true},
		{"bad quiet hours", func(c *Config) {
			c.Notify.QuietHours = QuietHours{Start: "25:99", End: "07:00"}
		}, true},
		{"negative schedule", func(c *Config) { c.Schedule["baseline"] = -5 }, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isolateEnv(t)
			cfg := Defaults()
			tt.mutate(cfg)
			err := cfg.Validate()
			if tt.wantErr && err == nil {
				t.Error("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestEffectiveStable(t *testing.T) {
	isolateEnv(t)
	cfg := Defaults()
	cfg.Notify.WebhookURL = "https://secret.example.com/abc123"
	out := cfg.Effective()
	if strings.Contains(out, "abc123") {
		t.Error("Effective should redact webhook URL")
	}
	if !strings.Contains(out, "source_url:") || !strings.Contains(out, "db_path:") {
		t.Errorf("Effective missing expected keys:\n%s", out)
	}
	// String mirrors Effective.
	if cfg.String() != out {
		t.Error("String should equal Effective")
	}
}

func TestYAMLParse_InlineAndBlockSequences(t *testing.T) {
	isolateEnv(t)
	writeConfig(t, `
# comment line
scan_roots: [/inline/a, "/inline/b"]
notify:
  channels:
    - terminal
    - desktop
`)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.ScanRoots) != 2 || cfg.ScanRoots[1] != "/inline/b" {
		t.Errorf("inline seq = %v", cfg.ScanRoots)
	}
	if len(cfg.Notify.Channels) != 2 || cfg.Notify.Channels[1] != "desktop" {
		t.Errorf("block seq = %v", cfg.Notify.Channels)
	}
}

// TestYAMLUnknownFieldRejected verifies that yaml.v3's KnownFields(true) is
// active: a typo in guardian.yaml surfaces as a parse error rather than being
// silently swallowed.
func TestYAMLUnknownFieldRejected(t *testing.T) {
	isolateEnv(t)
	writeConfig(t, `
catalog:
  source_url: https://example.com/catalog.json
  typo_field: oops
`)
	_, err := Load()
	if err == nil {
		t.Fatal("expected error for unknown yaml field, got nil")
	}
	if !strings.Contains(err.Error(), "typo_field") {
		t.Errorf("error should mention the offending field, got: %v", err)
	}
}

// TestYAMLScheduleBlock verifies that a schedule mapping in the file correctly
// overlays individual profile intervals while leaving unmentioned profiles at
// their defaults.
func TestYAMLScheduleBlock(t *testing.T) {
	isolateEnv(t)
	writeConfig(t, `
schedule:
  baseline: 15
  project: 5
`)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Schedule["baseline"] != 15 {
		t.Errorf("baseline = %d", cfg.Schedule["baseline"])
	}
	if cfg.Schedule["project"] != 5 {
		t.Errorf("project = %d", cfg.Schedule["project"])
	}
	// "deep" was not set in the file; default of 0 must still be present.
	if v, ok := cfg.Schedule["deep"]; !ok || v != 0 {
		t.Errorf("deep should remain at default 0, got ok=%v val=%d", ok, v)
	}
}

// TestYAMLEmptyFile verifies that an empty (or whitespace-only) config file
// leaves all defaults intact without returning an error.
func TestYAMLEmptyFile(t *testing.T) {
	isolateEnv(t)
	writeConfig(t, "\n# just a comment\n")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Catalog.SourceURL != DefaultCatalogSourceURL {
		t.Errorf("empty file changed source url: %q", cfg.Catalog.SourceURL)
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("empty file + defaults should validate: %v", err)
	}
}

// TestYAMLPartialOverlay confirms that writing only one field in the file
// leaves every other field at its default, exercising the nil-pointer overlay
// strategy in applyYAML.
func TestYAMLPartialOverlay(t *testing.T) {
	isolateEnv(t)
	writeConfig(t, `
retention:
  component_days: 7
`)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Retention.ComponentDays != 7 {
		t.Errorf("retention = %d", cfg.Retention.ComponentDays)
	}
	// Everything else must be untouched.
	if cfg.Catalog.SourceURL != DefaultCatalogSourceURL {
		t.Errorf("source url changed unexpectedly: %q", cfg.Catalog.SourceURL)
	}
	if cfg.Catalog.FreshnessTTL != DefaultFreshnessTTL {
		t.Errorf("ttl changed unexpectedly: %s", cfg.Catalog.FreshnessTTL)
	}
	if len(cfg.Notify.Channels) != 1 || cfg.Notify.Channels[0] != "terminal" {
		t.Errorf("channels changed unexpectedly: %v", cfg.Notify.Channels)
	}
}

// TestYAMLPrecedence_EnvWinsOverFile tests the full stack in one shot:
// file sets a value, env overrides it, result should be env's value.
func TestYAMLPrecedence_EnvWinsOverFile(t *testing.T) {
	isolateEnv(t)
	writeConfig(t, `
notify:
  min_severity: low
catalog:
  freshness_ttl: 48h
`)
	t.Setenv("GUARDIAN_NOTIFY_MIN_SEVERITY", "medium")
	t.Setenv("GUARDIAN_CATALOG_FRESHNESS_TTL", "1h")

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Notify.MinSeverity != "medium" {
		t.Errorf("env should override file for min_severity: %q", cfg.Notify.MinSeverity)
	}
	if cfg.Catalog.FreshnessTTL != time.Hour {
		t.Errorf("env should override file for freshness_ttl: %s", cfg.Catalog.FreshnessTTL)
	}
}
