package main

import (
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/wowtrust/trustdb/internal/tlcpbuild"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: trustdb-tlcp-build-record <oci-digest|oci-config-digest|normalize-sbom|record|verify>")
	}
	switch args[0] {
	case "oci-digest":
		flags := flag.NewFlagSet("oci-digest", flag.ContinueOnError)
		flags.SetOutput(stderr)
		var archive, platform string
		flags.StringVar(&archive, "oci-archive", "", "path to a single-platform OCI image archive")
		flags.StringVar(&platform, "platform", "", "expected OS/architecture")
		if err := parseFlags(flags, args[1:]); err != nil {
			return err
		}
		digest, err := tlcpbuild.OCIImageDigest(archive, platform)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(stdout, digest)
		return err
	case "oci-config-digest":
		flags := flag.NewFlagSet("oci-config-digest", flag.ContinueOnError)
		flags.SetOutput(stderr)
		var archive, platform string
		flags.StringVar(&archive, "oci-archive", "", "path to a single-platform OCI image archive")
		flags.StringVar(&platform, "platform", "", "expected OS/architecture")
		if err := parseFlags(flags, args[1:]); err != nil {
			return err
		}
		digest, err := tlcpbuild.OCIConfigDigest(archive, platform)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(stdout, digest)
		return err
	case "normalize-sbom":
		flags := flag.NewFlagSet("normalize-sbom", flag.ContinueOnError)
		flags.SetOutput(stderr)
		var baselinePath, inputPath, outputPath, imageDigest string
		flags.StringVar(&baselinePath, "baseline", "", "path to the pinned build baseline")
		flags.StringVar(&inputPath, "input", "", "path to raw Syft SPDX JSON")
		flags.StringVar(&outputPath, "output", "", "path for canonical SPDX JSON")
		flags.StringVar(&imageDigest, "image-digest", "", "OCI image manifest digest")
		if err := parseFlags(flags, args[1:]); err != nil {
			return err
		}
		baseline, _, err := tlcpbuild.LoadPinnedBaseline(baselinePath)
		if err != nil {
			return err
		}
		raw, err := os.ReadFile(inputPath)
		if err != nil {
			return fmt.Errorf("read raw SBOM: %w", err)
		}
		normalized, err := tlcpbuild.NormalizeSBOM(raw, baseline, imageDigest)
		if err != nil {
			return err
		}
		return writeFile(outputPath, normalized)
	case "record":
		flags := flag.NewFlagSet("record", flag.ContinueOnError)
		flags.SetOutput(stderr)
		var baselinePath, archivePath, sbomPath, platform, outputPath, checksumPath string
		flags.StringVar(&baselinePath, "baseline", "", "path to the pinned build baseline")
		flags.StringVar(&archivePath, "oci-archive", "", "path to the OCI image archive")
		flags.StringVar(&sbomPath, "sbom", "", "path to canonical SPDX JSON")
		flags.StringVar(&platform, "platform", "", "expected OS/architecture")
		flags.StringVar(&outputPath, "output", "", "path for the build record")
		flags.StringVar(&checksumPath, "checksum-output", "", "path for the build-record SHA-256")
		if err := parseFlags(flags, args[1:]); err != nil {
			return err
		}
		if _, _, err := tlcpbuild.LoadPinnedBaseline(baselinePath); err != nil {
			return err
		}
		record, err := tlcpbuild.CreateBuildRecord(
			baselinePath,
			archivePath,
			sbomPath,
			platform,
		)
		if err != nil {
			return err
		}
		data, err := tlcpbuild.EncodeBuildRecord(record)
		if err != nil {
			return err
		}
		if err := writeFile(outputPath, data); err != nil {
			return err
		}
		checksum := fmt.Sprintf("%x\n", sha256Bytes(data))
		return writeFile(checksumPath, []byte(checksum))
	case "verify":
		flags := flag.NewFlagSet("verify", flag.ContinueOnError)
		flags.SetOutput(stderr)
		var baselinePath, archivePath, sbomPath, platform, recordPath, checksumPath string
		flags.StringVar(&baselinePath, "baseline", "", "path to the pinned build baseline")
		flags.StringVar(&archivePath, "oci-archive", "", "path to the OCI image archive")
		flags.StringVar(&sbomPath, "sbom", "", "path to canonical SPDX JSON")
		flags.StringVar(&platform, "platform", "", "expected OS/architecture")
		flags.StringVar(&recordPath, "record", "", "path to the build record")
		flags.StringVar(&checksumPath, "record-sha256", "", "path to the build-record SHA-256")
		if err := parseFlags(flags, args[1:]); err != nil {
			return err
		}
		if _, _, err := tlcpbuild.LoadPinnedBaseline(baselinePath); err != nil {
			return err
		}
		if err := tlcpbuild.VerifyBuildRecord(
			recordPath,
			checksumPath,
			baselinePath,
			archivePath,
			sbomPath,
			platform,
		); err != nil {
			return err
		}
		_, err := fmt.Fprintln(stdout, "TLCP gateway build record verified")
		return err
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func parseFlags(flags *flag.FlagSet, args []string) error {
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	missing := ""
	flags.VisitAll(func(value *flag.Flag) {
		if value.Value.String() == "" && missing == "" {
			missing = "--" + value.Name
		}
	})
	if missing != "" {
		return fmt.Errorf("%s is required", missing)
	}
	return nil
}

func writeFile(path string, data []byte) error {
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

func sha256Bytes(data []byte) [32]byte {
	return sha256.Sum256(data)
}
