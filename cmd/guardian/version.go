package main

import (
	"github.com/spf13/cobra"

	"github.com/rmxventures/guardian/internal/scanner"
)

// Version is the guardian binary version. Override at build time with:
//
//	go build -ldflags "-X main.Version=v1.2.3" ./cmd/guardian
var Version = "0.1.0-dev"

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print guardian and scan-engine versions",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			sc := scanner.NewVendoredScanner()
			cmd.Printf("guardian %s\n", Version)
			cmd.Printf("scan engine (bumblebee) %s\n", sc.Version())
			return nil
		},
	}
}
