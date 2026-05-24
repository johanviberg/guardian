package service

import (
	"reflect"
	"strings"
	"testing"
)

func TestCronLines(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
		want []string
	}{
		{
			name: "15-minute baseline",
			cfg:  Config{Label: "io.guardian.agent", ExecPath: "/usr/local/bin/guardian", Args: []string{"scan", "baseline"}, IntervalMinutes: 15},
			want: []string{"*/15 * * * * /usr/local/bin/guardian scan baseline"},
		},
		{
			name: "hourly",
			cfg:  Config{Label: "l", ExecPath: "/bin/guardian", Args: []string{"run"}, IntervalMinutes: 60},
			want: []string{"0 */1 * * * /bin/guardian run"},
		},
		{
			name: "every 2 hours",
			cfg:  Config{Label: "l", ExecPath: "/bin/guardian", Args: nil, IntervalMinutes: 120},
			want: []string{"0 */2 * * * /bin/guardian"},
		},
		{
			name: "path with spaces gets quoted",
			cfg:  Config{Label: "l", ExecPath: "/opt/my apps/guardian", Args: []string{"scan", "baseline"}, IntervalMinutes: 30},
			want: []string{"*/30 * * * * '/opt/my apps/guardian' scan baseline"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CronLines(tt.cfg)
			if err != nil {
				t.Fatalf("CronLines: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("CronLines = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCronLinesInvalidInterval(t *testing.T) {
	if _, err := CronLines(Config{Label: "l", ExecPath: "/x", IntervalMinutes: 0}); err == nil {
		t.Error("expected error for zero interval")
	}
}

func TestMergeCrontabIdempotent(t *testing.T) {
	cfg := sampleConfig()
	block, err := (&cronManager{}).Render(cfg)
	if err != nil {
		t.Fatal(err)
	}

	existing := "# user job\n0 0 * * * /bin/backup.sh\n"

	// First install: appends managed block, preserves user content.
	first := mergeCrontab(existing, cfg.Label, block)
	if !strings.Contains(first, "/bin/backup.sh") {
		t.Errorf("install dropped pre-existing user crontab content:\n%s", first)
	}
	if strings.Count(first, ">>> guardian managed: io.guardian.agent >>>") != 1 {
		t.Errorf("expected exactly one managed block:\n%s", first)
	}

	// Re-install with the same label must NOT duplicate the block.
	second := mergeCrontab(first, cfg.Label, block)
	if strings.Count(second, ">>> guardian managed: io.guardian.agent >>>") != 1 {
		t.Errorf("re-install duplicated the managed block:\n%s", second)
	}
	if first != second {
		t.Errorf("re-install was not idempotent:\nfirst:\n%s\nsecond:\n%s", first, second)
	}

	// Different label coexists.
	cfg2 := cfg
	cfg2.Label = "io.guardian.project"
	block2, _ := (&cronManager{}).Render(cfg2)
	multi := mergeCrontab(second, cfg2.Label, block2)
	if !strings.Contains(multi, "io.guardian.agent") || !strings.Contains(multi, "io.guardian.project") {
		t.Errorf("expected both labels present:\n%s", multi)
	}
}

func TestRemoveCronBlock(t *testing.T) {
	cfg := sampleConfig()
	block, _ := (&cronManager{}).Render(cfg)
	existing := "# user job\n0 0 * * * /bin/backup.sh\n"
	withBlock := mergeCrontab(existing, cfg.Label, block)

	removed := removeCronBlock(withBlock, cfg.Label)
	if strings.Contains(removed, "guardian managed") {
		t.Errorf("block markers still present after removal:\n%s", removed)
	}
	if strings.Contains(removed, "/usr/local/bin/guardian") {
		t.Errorf("guardian line still present after removal:\n%s", removed)
	}
	if !strings.Contains(removed, "/bin/backup.sh") {
		t.Errorf("removal clobbered user content:\n%s", removed)
	}

	// Removing an absent block is a no-op.
	if again := removeCronBlock(removed, cfg.Label); again != removed {
		t.Errorf("removing absent block changed content:\n%s", again)
	}
}

func TestCronInstallUninstallExec(t *testing.T) {
	calls, restore := stubExec(t)
	defer restore()

	m := &cronManager{}
	if err := m.Install(sampleConfig()); err != nil {
		t.Fatalf("Install: %v", err)
	}

	// Expect: crontab -l (read), then crontab - (write via stdin).
	var wrote *recordedCmd
	for i := range *calls {
		c := (*calls)[i]
		if c.Name == "crontab" && len(c.Args) == 1 && c.Args[0] == "-" {
			wrote = &(*calls)[i]
		}
	}
	if wrote == nil {
		t.Fatalf("expected a `crontab -` write call, got %+v", *calls)
	}
	if !strings.Contains(wrote.Stdin, "*/15 * * * * /usr/local/bin/guardian scan baseline") {
		t.Errorf("crontab stdin missing expected line:\n%s", wrote.Stdin)
	}
	if !strings.Contains(wrote.Stdin, "guardian managed: io.guardian.agent") {
		t.Errorf("crontab stdin missing marker:\n%s", wrote.Stdin)
	}
}

func TestCronStatus(t *testing.T) {
	cfg := sampleConfig()
	block, _ := (&cronManager{}).Render(cfg)
	withBlock := mergeCrontab("# other\n", cfg.Label, block)

	origRun := runCommand
	defer func() { runCommand = origRun }()

	runCommand = func(name string, args ...string) ([]byte, error) {
		return []byte(withBlock), nil
	}
	ok, err := (&cronManager{}).Status(cfg.Label)
	if err != nil || !ok {
		t.Errorf("Status = (%v, %v), want (true, nil)", ok, err)
	}

	runCommand = func(name string, args ...string) ([]byte, error) {
		return []byte("# nothing here\n"), nil
	}
	ok, _ = (&cronManager{}).Status(cfg.Label)
	if ok {
		t.Error("Status = true for empty crontab, want false")
	}
}
