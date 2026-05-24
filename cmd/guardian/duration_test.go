package main

import (
	"testing"
	"time"
)

func TestParseExpiry(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    time.Duration
		wantErr bool
	}{
		{name: "days", input: "7d", want: 7 * 24 * time.Hour},
		{name: "single day", input: "1d", want: 24 * time.Hour},
		{name: "ninety days", input: "90d", want: 90 * 24 * time.Hour},
		{name: "weeks", input: "2w", want: 2 * 7 * 24 * time.Hour},
		{name: "single week", input: "1w", want: 7 * 24 * time.Hour},
		{name: "hours equals week", input: "168h", want: 168 * time.Hour},
		{name: "go composite", input: "1h30m", want: time.Hour + 30*time.Minute},
		{name: "minutes", input: "30m", want: 30 * time.Minute},

		{name: "empty", input: "", wantErr: true},
		{name: "whitespace only", input: "   ", wantErr: true},
		{name: "zero hours", input: "0h", wantErr: true},
		{name: "zero days", input: "0d", wantErr: true},
		{name: "negative hours", input: "-5h", wantErr: true},
		{name: "negative days", input: "-3d", wantErr: true},
		{name: "garbage", input: "abc", wantErr: true},
		{name: "missing number", input: "d", wantErr: true},
		{name: "float days unsupported", input: "1.5d", wantErr: true},
		{name: "bad unit", input: "7y", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseExpiry(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseExpiry(%q) = %v, want error", tt.input, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseExpiry(%q) unexpected error: %v", tt.input, err)
			}
			if got != tt.want {
				t.Errorf("parseExpiry(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}
