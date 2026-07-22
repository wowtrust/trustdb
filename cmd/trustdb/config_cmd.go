package main

import (
	"fmt"
	"os"

	trustconfig "github.com/wowtrust/trustdb/internal/config"
	"github.com/wowtrust/trustdb/internal/trusterr"
	"github.com/spf13/cobra"
)

func newConfigCommand(rt *runtimeConfig) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Manage TrustDB configuration",
	}
	cmd.AddCommand(newConfigInitCommand(rt))
	cmd.AddCommand(newConfigShowCommand(rt))
	cmd.AddCommand(newConfigValidateCommand(rt))
	return cmd
}

func newConfigInitCommand(rt *runtimeConfig) *cobra.Command {
	var outPath string
	var force bool
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Create a starter config file",
		RunE: func(cmd *cobra.Command, args []string) error {
			if outPath == "" {
				outPath = "trustdb.yaml"
			}
			if !force {
				if _, err := os.Stat(outPath); err == nil {
					return trusterr.New(trusterr.CodeAlreadyExists, fmt.Sprintf("config file already exists: %s", outPath))
				}
			}
			if err := writeFileAtomic(outPath, []byte(trustconfig.DefaultYAML), 0o600); err != nil {
				return err
			}
			return rt.writeJSON(map[string]string{"config": outPath})
		},
	}
	cmd.Flags().StringVar(&outPath, "out", "trustdb.yaml", "output config file")
	cmd.Flags().BoolVar(&force, "force", false, "overwrite existing config")
	return cmd
}

func newConfigShowCommand(rt *runtimeConfig) *cobra.Command {
	var showSensitive bool
	cmd := &cobra.Command{
		Use:   "show",
		Short: "Show the merged config used by this process",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := rt.cfg.Redacted()
			if showSensitive {
				cfg = rt.cfg
			}
			return rt.writeJSON(map[string]any{
				"config_file": rt.viper.ConfigFileUsed(),
				"redacted":    !showSensitive,
				"config":      cfg,
			})
		},
	}
	cmd.Flags().BoolVar(&showSensitive, "show-sensitive", false, "show sensitive config values")
	return cmd
}

func newConfigValidateCommand(rt *runtimeConfig) *cobra.Command {
	return &cobra.Command{
		Use:   "validate",
		Short: "Validate the merged config used by this process",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := rt.cfg.Validate(); err != nil {
				return trusterr.Wrap(trusterr.CodeInvalidArgument, "config validation failed", err)
			}
			return rt.writeJSON(map[string]any{
				"valid":       true,
				"config_file": rt.viper.ConfigFileUsed(),
			})
		},
	}
}
