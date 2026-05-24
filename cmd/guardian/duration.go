package main

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const (
	day  = 24 * time.Hour
	week = 7 * day
)

// parseExpiry parses an expiry duration string into a positive time.Duration.
//
// It accepts day and week suffixes that Go's time.ParseDuration does not
// understand:
//
//	Nd  -> N days  (a day is 24h)
//	Nw  -> N weeks (a week is 7*24h)
//
// for example "7d", "2w", or "90d". Any other input is delegated to
// time.ParseDuration, so standard Go durations such as "168h", "30m", and
// "1h30m" continue to work.
//
// Empty, zero, and negative durations are rejected with a descriptive error.
func parseExpiry(s string) (time.Duration, error) {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return 0, errors.New("expiry must not be empty")
	}

	d, err := parseDuration(trimmed)
	if err != nil {
		return 0, err
	}
	if d <= 0 {
		return 0, fmt.Errorf("expiry must be positive, got %q", s)
	}
	return d, nil
}

// parseDuration handles the day/week suffixes and otherwise falls back to
// time.ParseDuration. It does not enforce sign or non-zero; that is the
// responsibility of parseExpiry.
func parseDuration(s string) (time.Duration, error) {
	if unit, ok := trailingUnit(s); ok {
		numStr := s[:len(s)-1]
		n, err := strconv.ParseInt(numStr, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid duration %q: %w", s, err)
		}
		return time.Duration(n) * unit, nil
	}

	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid duration %q: accepts Go durations (e.g. 168h, 1h30m) or day/week units (e.g. 7d, 2w)", s)
	}
	return d, nil
}

// trailingUnit reports whether s ends in a recognized day/week unit suffix and,
// if so, the time.Duration that suffix represents.
func trailingUnit(s string) (time.Duration, bool) {
	if len(s) < 2 {
		return 0, false
	}
	switch s[len(s)-1] {
	case 'd':
		return day, true
	case 'w':
		return week, true
	default:
		return 0, false
	}
}
