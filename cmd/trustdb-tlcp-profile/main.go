package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/wowtrust/trustdb/internal/tlcpprofile"
)

type stringList []string

func (values *stringList) String() string { return strings.Join(*values, ",") }

func (values *stringList) Set(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return errors.New("value must not be empty")
	}
	*values = append(*values, value)
	return nil
}

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New(
			"usage: trustdb-tlcp-profile <validate|timeout|prepare-runtime|verify-runtime>",
		)
	}
	if args[0] == "prepare-runtime" || args[0] == "verify-runtime" {
		return runRuntime(args[0], args[1:], stdout, stderr)
	}
	if args[0] == "timeout" {
		return runTimeout(args[1:], stdout, stderr)
	}
	if args[0] != "validate" {
		return fmt.Errorf("unknown command %q", args[0])
	}
	flags := flag.NewFlagSet("validate", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var profilePath string
	var forbiddenReferences stringList
	var forbiddenPublicKeys stringList
	flags.StringVar(&profilePath, "profile", "", "absolute path to a TLCP gateway profile")
	flags.Var(&forbiddenReferences, "forbid-key-ref", "proof-signing key reference that the gateway must not reuse; may be repeated")
	flags.Var(
		&forbiddenPublicKeys,
		"forbid-public-key-sha256",
		"canonical proof-signing public-key SHA-256 that the gateway must not reuse; may be repeated",
	)
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	profilePath = strings.TrimSpace(profilePath)
	if profilePath == "" {
		return errors.New("--profile is required")
	}
	_, report, err := tlcpprofile.LoadAndValidate(profilePath, tlcpprofile.Options{
		ForbiddenKeyReferences:    append([]string(nil), forbiddenReferences...),
		ForbiddenPublicKeySHA256s: append([]string(nil), forbiddenPublicKeys...),
	})
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(report); err != nil {
		return fmt.Errorf("encode TLCP gateway validation report: %w", err)
	}
	return nil
}

func runTimeout(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("timeout", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var profilePath, lifecycle string
	flags.StringVar(&profilePath, "profile", "", "absolute path to the strict TLCP gateway profile")
	flags.StringVar(
		&lifecycle,
		"lifecycle",
		"",
		"lifecycle deadline to emit: startup, reload, or canary",
	)
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	if strings.TrimSpace(profilePath) == "" || strings.TrimSpace(lifecycle) == "" {
		return errors.New("--profile and --lifecycle are required")
	}
	profile, _, err := tlcpprofile.LoadAndValidate(profilePath, tlcpprofile.Options{})
	if err != nil {
		return err
	}
	timeout, err := tlcpprofile.LifecycleTimeout(profile, lifecycle)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, timeout.String())
	return err
}

func runRuntime(command string, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(stderr)
	var profilePath, imageDigest, configurationPath, manifestPath string
	flags.StringVar(&profilePath, "profile", "", "absolute path to the strict TLCP gateway profile")
	flags.StringVar(&imageDigest, "expected-image-digest", "", "deployed OCI image manifest digest")
	flags.StringVar(&configurationPath, "configuration", "", "absolute runtime nginx configuration path")
	flags.StringVar(&manifestPath, "runtime-manifest", "", "absolute validated runtime manifest path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	for name, value := range map[string]string{
		"--profile":               profilePath,
		"--expected-image-digest": imageDigest,
		"--configuration":         configurationPath,
		"--runtime-manifest":      manifestPath,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s is required", name)
		}
	}
	options := tlcpprofile.RuntimeOptions{
		ExpectedGatewayImageDigest: imageDigest,
		ConfigurationPath:          configurationPath,
		ManifestPath:               manifestPath,
	}
	var (
		manifest tlcpprofile.RuntimeManifest
		err      error
	)
	if command == "prepare-runtime" {
		manifest, err = tlcpprofile.PrepareRuntime(profilePath, options)
	} else {
		manifest, err = tlcpprofile.VerifyRuntime(profilePath, options)
	}
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(manifest)
}
