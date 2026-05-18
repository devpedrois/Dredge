package cli

import (
	"errors"
	"fmt"
	"log/slog"

	"github.com/spf13/cobra"
	"github.com/user/dredge/internal/config"
	"github.com/user/dredge/internal/docker"
	"github.com/user/dredge/internal/logger"
)

// ErrPendingDeletions is returned by the plan command when there are resources
// to delete. main.go translates this to exit code 1, enabling scripting:
//
//	dredge plan || dredge sweep --yes
//
// Using a sentinel error instead of os.Exit(1) inside RunE ensures that all
// defers run correctly and the function remains unit-testable.
var ErrPendingDeletions = errors.New("pending deletions found")

// AppContext holds initialized dependencies shared across all subcommands.
type AppContext struct {
	Config *config.Config
	Logger *slog.Logger
	Docker *docker.Client
}

var appCtx *AppContext

var (
	flagConfig   string
	flagSocket   string
	flagLogLevel string
	flagFormat   string
)

var rootCmd = &cobra.Command{
	Use:   "dredge",
	Short: "Docker garbage collector with brains",
	Long:  "dredge — Smart cleanup for Docker: policies, dependency graph, and dry-run.",

	PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
		cfg, err := config.Load(flagConfig)
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}

		// CLI flags override config values.
		if flagSocket != "" {
			cfg.Docker.Socket = flagSocket
		}
		if flagLogLevel != "" {
			cfg.Logging.Level = flagLogLevel
		}

		log := logger.New(cfg.Logging.Level, cfg.Logging.Format)

		dockerClient, err := docker.NewClient(cfg.Docker.Socket, cfg.Docker.Timeout, log)
		if err != nil {
			return fmt.Errorf("connecting to Docker: %w", err)
		}

		appCtx = &AppContext{
			Config: cfg,
			Logger: log,
			Docker: dockerClient,
		}
		return nil
	},
}

// Execute runs the root cobra command.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.PersistentFlags().StringVar(&flagConfig, "config", "", "Config file path")
	rootCmd.PersistentFlags().StringVar(&flagSocket, "socket", "", "Docker socket path (overrides config)")
	rootCmd.PersistentFlags().StringVar(&flagLogLevel, "log-level", "info", "Log level: debug, info, warn, error")
	rootCmd.PersistentFlags().StringVar(&flagFormat, "format", "table", "Output format: table, json")

	rootCmd.AddCommand(planCmd)
	rootCmd.AddCommand(sweepCmd)
	rootCmd.AddCommand(watchCmd)
	rootCmd.AddCommand(statsCmd)
}

