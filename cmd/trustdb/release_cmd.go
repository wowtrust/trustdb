package main

import (
	"encoding/json"
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/wowtrust/trustdb/internal/supplychain"
)

func newReleaseCommand(rt *runtimeConfig) *cobra.Command {
	command := &cobra.Command{
		Use:   "release",
		Short: "Create and verify fail-closed release supply-chain evidence",
	}
	command.AddCommand(newReleaseManifestCommand(rt))
	command.AddCommand(newReleaseVerifyCommand(rt))
	command.AddCommand(newReleasePolicyCommand(rt))
	command.AddCommand(newReleaseDigestCommand(rt))
	command.AddCommand(newReleaseArchiveCommand(rt))
	return command
}

func newReleaseArchiveCommand(rt *runtimeConfig) *cobra.Command {
	var (
		source    string
		output    string
		format    string
		timestamp string
	)
	command := &cobra.Command{
		Use:   "archive",
		Short: "Create a deterministic tar.gz or zip distribution archive",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := supplychain.WriteArchive(source, output, format, timestamp); err != nil {
				return err
			}
			return writeReleaseResult(rt, map[string]any{
				"archive": output, "format": format, "timestamp": timestamp,
			})
		},
	}
	command.Flags().StringVar(&source, "source", "", "package root directory")
	command.Flags().StringVar(&output, "output", "", "archive output path")
	command.Flags().StringVar(&format, "format", "", "archive format: tar.gz or zip")
	command.Flags().StringVar(&timestamp, "timestamp", "", "fixed RFC 3339 archive timestamp")
	_ = command.MarkFlagRequired("source")
	_ = command.MarkFlagRequired("output")
	_ = command.MarkFlagRequired("format")
	_ = command.MarkFlagRequired("timestamp")
	return command
}

func newReleaseDigestCommand(rt *runtimeConfig) *cobra.Command {
	var (
		root string
		path string
	)
	command := &cobra.Command{
		Use:   "digest-input",
		Short: "Calculate the canonical SHA-256 for one production input",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			digest, err := supplychain.DigestPath(root, path)
			if err != nil {
				return err
			}
			return writeReleaseResult(rt, map[string]any{"path": path, "sha256": digest})
		},
	}
	command.Flags().StringVar(&root, "root", ".", "repository root")
	command.Flags().StringVar(&path, "path", "", "repository-relative file or directory")
	_ = command.MarkFlagRequired("path")
	return command
}

func newReleaseManifestCommand(rt *runtimeConfig) *cobra.Command {
	var (
		directory         string
		version           string
		commit            string
		buildDate         string
		policyPath        string
		requiredDocuments []string
	)
	command := &cobra.Command{
		Use:   "manifest",
		Short: "Generate a versioned manifest plus SHA-256 and SM3 checksum files",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			manifest, err := supplychain.Generate(supplychain.GenerateOptions{
				Directory: directory, Version: version, Commit: commit, BuildDate: buildDate,
				PolicyPath: policyPath, RequiredDocuments: requiredDocuments,
			})
			if err != nil {
				return err
			}
			if err := supplychain.Write(directory, manifest); err != nil {
				return err
			}
			return writeReleaseResult(rt, map[string]any{
				"schema":            manifest.Schema,
				"manifest":          filepath.Join(directory, supplychain.ManifestFilename),
				"sha256_checksums":  filepath.Join(directory, supplychain.SHA256Filename),
				"sm3_checksums":     filepath.Join(directory, supplychain.SM3Filename),
				"artifact_count":    len(manifest.Artifacts),
				"source_commit":     manifest.Source.Commit,
				"production_policy": manifest.PolicySHA256,
			})
		},
	}
	command.Flags().StringVar(&directory, "dir", "", "flat directory containing release artifacts")
	command.Flags().StringVar(&version, "version", "", "release version without the leading v")
	command.Flags().StringVar(&commit, "commit", "", "exact 40-character source commit")
	command.Flags().StringVar(&buildDate, "build-date", "", "reproducible RFC 3339 build timestamp")
	command.Flags().StringVar(&policyPath, "policy", "supply-chain/production-inputs.json", "validated production-input policy")
	command.Flags().StringSliceVar(&requiredDocuments, "require", nil, "required release metadata filename (repeatable)")
	_ = command.MarkFlagRequired("dir")
	_ = command.MarkFlagRequired("version")
	_ = command.MarkFlagRequired("commit")
	_ = command.MarkFlagRequired("build-date")
	return command
}

func newReleaseVerifyCommand(rt *runtimeConfig) *cobra.Command {
	var directory string
	command := &cobra.Command{
		Use:   "verify",
		Short: "Offline-verify exact artifact coverage, sizes, SHA-256, and SM3",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			manifest, err := supplychain.Read(filepath.Join(directory, supplychain.ManifestFilename))
			if err != nil {
				return err
			}
			if err := supplychain.Verify(directory, manifest); err != nil {
				return err
			}
			return writeReleaseResult(rt, map[string]any{
				"verified":       true,
				"schema":         manifest.Schema,
				"version":        manifest.Version,
				"source_commit":  manifest.Source.Commit,
				"artifact_count": len(manifest.Artifacts),
			})
		},
	}
	command.Flags().StringVar(&directory, "dir", "", "release bundle directory")
	_ = command.MarkFlagRequired("dir")
	return command
}

func newReleasePolicyCommand(rt *runtimeConfig) *cobra.Command {
	var (
		root       string
		policyPath string
	)
	command := &cobra.Command{
		Use:   "verify-policy",
		Short: "Verify pinned production inputs, licenses, architectures, mirrors, actions, and images",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := supplychain.ValidatePolicy(root, policyPath); err != nil {
				return err
			}
			return writeReleaseResult(rt, map[string]any{
				"verified": true,
				"schema":   supplychain.PolicySchema,
				"policy":   policyPath,
			})
		},
	}
	command.Flags().StringVar(&root, "root", ".", "repository root")
	command.Flags().StringVar(&policyPath, "policy", "supply-chain/production-inputs.json", "production-input policy path")
	return command
}

func writeReleaseResult(rt *runtimeConfig, result map[string]any) error {
	encoded, err := json.Marshal(result)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(rt.out, string(encoded))
	return err
}
