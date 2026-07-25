package main

import (
	"os"
	"path/filepath"
	"runtime"

	"github.com/spf13/cobra"
	"github.com/wowtrust/trustdb/internal/adminauth"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func newVersionCommand(rt *runtimeConfig) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Show build version information",
		RunE: func(cmd *cobra.Command, args []string) error {
			return rt.writeJSON(map[string]string{
				"version": version,
				"commit":  commit,
				"date":    date,
				"go":      runtime.Version(),
				"os":      runtime.GOOS,
				"arch":    runtime.GOARCH,
			})
		},
	}
}

func newDoctorCommand(rt *runtimeConfig) *cobra.Command {
	return requirePermission(&cobra.Command{
		Use:   "doctor",
		Short: "Run local configuration and filesystem diagnostics",
		RunE: func(cmd *cobra.Command, args []string) error {
			checks := []map[string]any{
				checkConfig(rt),
				checkDir("paths.data_dir", rt.cfg.Paths.DataDir),
				checkParentDir("paths.wal", rt.cfg.Paths.WAL),
				checkParentDir("paths.key_registry", rt.cfg.Paths.KeyRegistry),
				checkDir("paths.object_dir", rt.cfg.Paths.ObjectDir),
				checkParentDir("log.file.path", rt.cfg.Log.File.Path),
			}
			ok := true
			for _, check := range checks {
				if check["ok"] != true {
					ok = false
					break
				}
			}
			return rt.writeJSON(map[string]any{
				"ok":     ok,
				"checks": checks,
			})
		},
	}, adminauth.PermissionSystemRead)
}

func newCompletionCommand(rt *runtimeConfig) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "completion [bash|zsh|fish|powershell]",
		Short: "Generate shell completion script",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			root := cmd.Root()
			switch args[0] {
			case "bash":
				return root.GenBashCompletion(rt.out)
			case "zsh":
				return root.GenZshCompletion(rt.out)
			case "fish":
				return root.GenFishCompletion(rt.out, true)
			case "powershell":
				return root.GenPowerShellCompletion(rt.out)
			default:
				return usageError("completion shell must be one of bash, zsh, fish, powershell")
			}
		},
	}
	return cmd
}

func checkConfig(rt *runtimeConfig) map[string]any {
	if err := rt.cfg.Validate(); err != nil {
		return map[string]any{"name": "config", "ok": false, "error": err.Error()}
	}
	return map[string]any{"name": "config", "ok": true}
}

func checkDir(name, path string) map[string]any {
	if path == "" {
		return map[string]any{"name": name, "ok": true, "skipped": true}
	}
	info, err := os.Stat(path)
	if err != nil {
		return map[string]any{"name": name, "ok": false, "path": path, "error": err.Error()}
	}
	if !info.IsDir() {
		return map[string]any{"name": name, "ok": false, "path": path, "error": "not a directory"}
	}
	return map[string]any{"name": name, "ok": true, "path": path}
}

func checkParentDir(name, path string) map[string]any {
	if path == "" {
		return map[string]any{"name": name, "ok": true, "skipped": true}
	}
	parent := filepath.Dir(path)
	if parent == "." {
		return map[string]any{"name": name, "ok": true, "path": path}
	}
	check := checkDir(name, parent)
	check["path"] = path
	check["parent"] = parent
	return check
}
