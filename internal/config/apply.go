package config

import (
	"fmt"
	"strconv"
	"time"
)

// applyYAML overlays a parsed YAML document onto cfg. Only keys present in the
// document are touched; absent keys retain their prior (default) values.
func applyYAML(cfg *Config, doc *yamlNode) error {
	if doc == nil || !doc.isMapping() {
		return fmt.Errorf("yaml: top-level document must be a mapping")
	}

	if n := doc.mapping["scan_roots"]; n != nil {
		roots, err := scalarSlice("scan_roots", n)
		if err != nil {
			return err
		}
		cfg.ScanRoots = roots
	}

	if n := doc.mapping["schedule"]; n != nil {
		if !n.isMapping() {
			return fmt.Errorf("yaml: schedule must be a mapping")
		}
		if cfg.Schedule == nil {
			cfg.Schedule = map[string]int{}
		}
		for profile, vn := range n.mapping {
			mins, err := scalarInt("schedule."+profile, vn)
			if err != nil {
				return err
			}
			cfg.Schedule[profile] = mins
		}
	}

	if n := doc.mapping["catalog"]; n != nil {
		if err := applyCatalog(cfg, n); err != nil {
			return err
		}
	}
	if n := doc.mapping["notify"]; n != nil {
		if err := applyNotify(cfg, n); err != nil {
			return err
		}
	}
	if n := doc.mapping["retention"]; n != nil {
		if !n.isMapping() {
			return fmt.Errorf("yaml: retention must be a mapping")
		}
		if v := n.mapping["component_days"]; v != nil {
			days, err := scalarInt("retention.component_days", v)
			if err != nil {
				return err
			}
			cfg.Retention.ComponentDays = days
		}
	}

	if n := doc.mapping["db_path"]; n != nil {
		s, err := scalarString("db_path", n)
		if err != nil {
			return err
		}
		cfg.DBPath = s
	}
	if n := doc.mapping["state_dir"]; n != nil {
		s, err := scalarString("state_dir", n)
		if err != nil {
			return err
		}
		cfg.StateDir = s
	}
	return nil
}

func applyCatalog(cfg *Config, n *yamlNode) error {
	if !n.isMapping() {
		return fmt.Errorf("yaml: catalog must be a mapping")
	}
	if v := n.mapping["source_url"]; v != nil {
		s, err := scalarString("catalog.source_url", v)
		if err != nil {
			return err
		}
		cfg.Catalog.SourceURL = s
	}
	if v := n.mapping["freshness_ttl"]; v != nil {
		s, err := scalarString("catalog.freshness_ttl", v)
		if err != nil {
			return err
		}
		d, err := time.ParseDuration(s)
		if err != nil {
			return fmt.Errorf("yaml: catalog.freshness_ttl: %w", err)
		}
		cfg.Catalog.FreshnessTTL = d
	}
	if v := n.mapping["cache_dir"]; v != nil {
		s, err := scalarString("catalog.cache_dir", v)
		if err != nil {
			return err
		}
		cfg.Catalog.CacheDir = s
	}
	return nil
}

func applyNotify(cfg *Config, n *yamlNode) error {
	if !n.isMapping() {
		return fmt.Errorf("yaml: notify must be a mapping")
	}
	if v := n.mapping["channels"]; v != nil {
		ch, err := scalarSlice("notify.channels", v)
		if err != nil {
			return err
		}
		cfg.Notify.Channels = ch
	}
	if v := n.mapping["webhook_url"]; v != nil {
		s, err := scalarString("notify.webhook_url", v)
		if err != nil {
			return err
		}
		cfg.Notify.WebhookURL = s
	}
	if v := n.mapping["min_severity"]; v != nil {
		s, err := scalarString("notify.min_severity", v)
		if err != nil {
			return err
		}
		cfg.Notify.MinSeverity = s
	}
	if v := n.mapping["quiet_hours"]; v != nil {
		if !v.isMapping() {
			return fmt.Errorf("yaml: notify.quiet_hours must be a mapping")
		}
		if s := v.mapping["start"]; s != nil {
			str, err := scalarString("notify.quiet_hours.start", s)
			if err != nil {
				return err
			}
			cfg.Notify.QuietHours.Start = str
		}
		if e := v.mapping["end"]; e != nil {
			str, err := scalarString("notify.quiet_hours.end", e)
			if err != nil {
				return err
			}
			cfg.Notify.QuietHours.End = str
		}
	}
	return nil
}

func scalarString(key string, n *yamlNode) (string, error) {
	if n.isMapping() || n.isSequence() {
		return "", fmt.Errorf("yaml: %s must be a scalar", key)
	}
	return n.scalar, nil
}

func scalarInt(key string, n *yamlNode) (int, error) {
	s, err := scalarString(key, n)
	if err != nil {
		return 0, err
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("yaml: %s must be an integer: %w", key, err)
	}
	return v, nil
}

func scalarSlice(key string, n *yamlNode) ([]string, error) {
	if !n.isSequence() {
		return nil, fmt.Errorf("yaml: %s must be a sequence", key)
	}
	return append([]string(nil), n.sequence...), nil
}
