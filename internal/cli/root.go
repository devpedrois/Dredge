package cli

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/spf13/cobra"
	"github.com/user/dredge/internal/config"
	"github.com/user/dredge/internal/docker"
	"github.com/user/dredge/internal/logger"
)

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

// exitOnError prints the error and exits with code 1.
// Use this after defers have run — do NOT use log.Fatal.
func exitOnError(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
