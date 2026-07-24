package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

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
			"usage: trustdb-tlcp-profile <validate|timeout|activate-runtime|prepare-runtime|verify-runtime>",
		)
	}
	if args[0] == "activate-runtime" {
		return runActivateRuntime(args[1:], stdout, stderr)
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
	timeoutSeconds, err := tlcpprofile.LifecycleTimeoutSeconds(profile, lifecycle)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, timeoutSeconds)
	return err
}

const maxActivationCommandOutputBytes = 64 << 10

type activationOptions struct {
	profilePath       string
	lifecycle         string
	imageDigest       string
	configuration     string
	manifest          string
	gateway           string
	gatewayPrefix     string
	currentExecutable string
}

func runActivateRuntime(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("activate-runtime", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var options activationOptions
	flags.StringVar(&options.profilePath, "profile", "", "absolute path to the strict TLCP gateway profile")
	flags.StringVar(&options.lifecycle, "lifecycle", "", "startup or reload deadline")
	flags.StringVar(&options.imageDigest, "expected-image-digest", "", "deployed OCI image manifest digest")
	flags.StringVar(&options.configuration, "configuration", "", "absolute active nginx configuration path")
	flags.StringVar(&options.manifest, "runtime-manifest", "", "absolute active runtime manifest path")
	flags.StringVar(&options.gateway, "gateway", "", "absolute TLCP gateway executable path")
	flags.StringVar(&options.gatewayPrefix, "gateway-prefix", "", "absolute TLCP gateway runtime prefix")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	for name, value := range map[string]string{
		"--profile":               options.profilePath,
		"--lifecycle":             options.lifecycle,
		"--expected-image-digest": options.imageDigest,
		"--configuration":         options.configuration,
		"--runtime-manifest":      options.manifest,
		"--gateway":               options.gateway,
		"--gateway-prefix":        options.gatewayPrefix,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s is required", name)
		}
	}
	if options.lifecycle != tlcpprofile.LifecycleStartup &&
		options.lifecycle != tlcpprofile.LifecycleReload {
		return errors.New("--lifecycle must be startup or reload")
	}
	for name, value := range map[string]string{
		"--gateway":        options.gateway,
		"--gateway-prefix": options.gatewayPrefix,
	} {
		if !filepath.IsAbs(value) || filepath.Clean(value) != value {
			return fmt.Errorf("%s must be an absolute clean path", name)
		}
	}
	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve TLCP profile executable: %w", err)
	}
	options.currentExecutable = executable
	return activateRuntime(options, stdout, stderr, time.Now)
}

func activateRuntime(
	options activationOptions,
	stdout, stderr io.Writer,
	now func() time.Time,
) error {
	started := now()
	profile, _, err := tlcpprofile.LoadAndValidate(
		options.profilePath,
		tlcpprofile.Options{},
	)
	if err != nil {
		return err
	}
	deadline, err := validatedLifecycleDeadline(
		started,
		now(),
		profile,
		options.lifecycle,
	)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()

	suffix := fmt.Sprintf(".next.%d", os.Getpid())
	nextConfiguration := options.configuration + suffix
	nextManifest := options.manifest + suffix
	defer os.Remove(nextConfiguration)
	defer os.Remove(nextManifest)

	prepare := exec.CommandContext(
		ctx,
		options.currentExecutable,
		"prepare-runtime",
		"--profile", options.profilePath,
		"--expected-image-digest", options.imageDigest,
		"--configuration", nextConfiguration,
		"--runtime-manifest", nextManifest,
	)
	if err := runActivationCommand(prepare); err != nil {
		return activationCommandError(ctx, "prepare TLCP runtime", err)
	}
	validate := exec.CommandContext(
		ctx,
		options.gateway,
		"-t",
		"-c", nextConfiguration,
		"-p", options.gatewayPrefix,
	)
	if err := runActivationCommand(validate); err != nil {
		return activationCommandError(ctx, "validate TLCP gateway configuration", err)
	}
	if err := os.Rename(nextConfiguration, options.configuration); err != nil {
		return fmt.Errorf("activate TLCP gateway configuration: %w", err)
	}
	if err := os.Rename(nextManifest, options.manifest); err != nil {
		return fmt.Errorf("activate TLCP runtime manifest: %w", err)
	}
	_, err = fmt.Fprintf(stdout, "TLCP %s runtime activated\n", options.lifecycle)
	return err
}

func validatedLifecycleDeadline(
	started time.Time,
	validated time.Time,
	profile tlcpprofile.Profile,
	lifecycle string,
) (time.Time, error) {
	timeout, err := tlcpprofile.LifecycleTimeout(profile, lifecycle)
	if err != nil {
		return time.Time{}, err
	}
	deadline := started.Add(timeout)
	if !validated.Before(deadline) {
		return time.Time{}, fmt.Errorf(
			"TLCP %s deadline expired during initial profile validation",
			lifecycle,
		)
	}
	return deadline, nil
}

func activationCommandError(ctx context.Context, action string, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return fmt.Errorf("%s: lifecycle deadline exceeded: %w", action, ctxErr)
	}
	return fmt.Errorf("%s: %w", action, err)
}

func runActivationCommand(command *exec.Cmd) error {
	output := &boundedActivationOutput{limit: maxActivationCommandOutputBytes}
	command.Stdout = output
	command.Stderr = output
	if err := command.Run(); err != nil {
		diagnostics := strings.TrimSpace(string(output.Bytes()))
		if diagnostics == "" {
			return err
		}
		return fmt.Errorf("%w: %s", err, diagnostics)
	}
	if output.Exceeded() {
		return fmt.Errorf(
			"command output exceeds %d bytes",
			maxActivationCommandOutputBytes,
		)
	}
	return nil
}

type boundedActivationOutput struct {
	mutex    sync.Mutex
	data     []byte
	limit    int
	exceeded bool
}

func (output *boundedActivationOutput) Write(data []byte) (int, error) {
	output.mutex.Lock()
	defer output.mutex.Unlock()
	remaining := output.limit - len(output.data)
	if remaining <= 0 {
		output.exceeded = true
		return 0, errors.New("activation command output limit exceeded")
	}
	if len(data) > remaining {
		output.data = append(output.data, data[:remaining]...)
		output.exceeded = true
		return remaining, errors.New("activation command output limit exceeded")
	}
	output.data = append(output.data, data...)
	return len(data), nil
}

func (output *boundedActivationOutput) Bytes() []byte {
	output.mutex.Lock()
	defer output.mutex.Unlock()
	return append([]byte(nil), output.data...)
}

func (output *boundedActivationOutput) Exceeded() bool {
	output.mutex.Lock()
	defer output.mutex.Unlock()
	return output.exceeded
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
