package config

import (
	"bytes"
	"fmt"
	"io"
	"time"

	"gopkg.in/yaml.v3"
)

// fileConfig is the intermediate representation of guardian.yaml. Every field
// is a pointer so that yaml.v3 leaves absent keys as nil — allowing applyYAML
// to distinguish "not set in file" from "set to zero value", and therefore
// overlay only the keys the user actually wrote.
//
// yaml.v3 with KnownFields(true) will reject any key not present in this
// struct, surfacing typos in the config file as an error.
type fileConfig struct {
	ScanRoots []string       `yaml:"scan_roots"`
	Schedule  map[string]int `yaml:"schedule"`
	Catalog   *fileCatalog   `yaml:"catalog"`
	Notify    *fileNotify    `yaml:"notify"`
	Retention *fileRetention `yaml:"retention"`
	DBPath    *string        `yaml:"db_path"`
	StateDir  *string        `yaml:"state_dir"`
}

type fileCatalog struct {
	SourceURL    *string `yaml:"source_url"`
	FreshnessTTL *string `yaml:"freshness_ttl"` // parsed as Go duration string
	CacheDir     *string `yaml:"cache_dir"`
	Verify       *string `yaml:"verify"`
	PublicKey    *string `yaml:"public_key"`
}

type fileNotify struct {
	Channels    []string        `yaml:"channels"`
	WebhookURL  *string         `yaml:"webhook_url"`
	MinSeverity *string         `yaml:"min_severity"`
	QuietHours  *fileQuietHours `yaml:"quiet_hours"`
}

type fileQuietHours struct {
	Start *string `yaml:"start"`
	End   *string `yaml:"end"`
}

type fileRetention struct {
	ComponentDays *int `yaml:"component_days"`
}

// applyYAML unmarshals raw YAML bytes into the intermediate fileConfig and
// overlays each present field onto cfg. It rejects unknown top-level keys.
func applyYAML(cfg *Config, data []byte) error {
	var fc fileConfig
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&fc); err != nil {
		// An empty or comment-only file produces io.EOF; treat as no-op.
		if err == io.EOF {
			return nil
		}
		return fmt.Errorf("parse: %w", err)
	}

	if fc.ScanRoots != nil {
		cfg.ScanRoots = append([]string(nil), fc.ScanRoots...)
	}
	if fc.Schedule != nil {
		if cfg.Schedule == nil {
			cfg.Schedule = make(map[string]int, len(fc.Schedule))
		}
		for profile, mins := range fc.Schedule {
			cfg.Schedule[profile] = mins
		}
	}
	if c := fc.Catalog; c != nil {
		if c.SourceURL != nil {
			cfg.Catalog.SourceURL = *c.SourceURL
		}
		if c.FreshnessTTL != nil {
			d, err := time.ParseDuration(*c.FreshnessTTL)
			if err != nil {
				return fmt.Errorf("catalog.freshness_ttl: %w", err)
			}
			cfg.Catalog.FreshnessTTL = d
		}
		if c.CacheDir != nil {
			cfg.Catalog.CacheDir = *c.CacheDir
		}
		if c.Verify != nil {
			cfg.Catalog.Verify = *c.Verify
		}
		if c.PublicKey != nil {
			cfg.Catalog.PublicKey = *c.PublicKey
		}
	}
	if n := fc.Notify; n != nil {
		if n.Channels != nil {
			cfg.Notify.Channels = append([]string(nil), n.Channels...)
		}
		if n.WebhookURL != nil {
			cfg.Notify.WebhookURL = *n.WebhookURL
		}
		if n.MinSeverity != nil {
			cfg.Notify.MinSeverity = *n.MinSeverity
		}
		if qh := n.QuietHours; qh != nil {
			if qh.Start != nil {
				cfg.Notify.QuietHours.Start = *qh.Start
			}
			if qh.End != nil {
				cfg.Notify.QuietHours.End = *qh.End
			}
		}
	}
	if r := fc.Retention; r != nil {
		if r.ComponentDays != nil {
			cfg.Retention.ComponentDays = *r.ComponentDays
		}
	}
	if fc.DBPath != nil {
		cfg.DBPath = *fc.DBPath
	}
	if fc.StateDir != nil {
		cfg.StateDir = *fc.StateDir
	}
	return nil
}
