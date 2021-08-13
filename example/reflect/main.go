package main

import (
	"github.com/michaelquigley/pfxlog"
	"github.com/qrkourier/sdk-golang/example/reflect/cmd"
	"github.com/qrkourier/sdk-golang/ziti/config"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var log = pfxlog.Logger()
var verbose bool

var rootCmd = &cobra.Command{Use: "app"}

func main() {
	logrus.SetFormatter(&logrus.TextFormatter{
		ForceColors:      true,
		DisableTimestamp: true,
		TimestampFormat:  "",
		PadLevelText:     true,
	})
	logrus.SetReportCaller(false)

	rootCmd.PersistentPreRun = func(cmd *cobra.Command, args []string) {
		if verbose {
			logrus.SetLevel(logrus.DebugLevel)
		}
	}
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose logging")
	rootCmd.PersistentFlags().StringP("identity", "i", "", "REQUIRED: Path to JSON file that contains an enrolled identity")
	rootCmd.PersistentFlags().StringP("serviceName", "s", "", "REQUIRED: The service to host")

	_ = cobra.MarkFlagRequired(rootCmd.PersistentFlags(), "identity")
	_ = cobra.MarkFlagRequired(rootCmd.PersistentFlags(), "serviceName")

	var serverCmd = &cobra.Command{
		Use:   "server",
		Short: "run the process as a server",
		Run: func(subcmd *cobra.Command, args []string) {
			cmd.Server(getConfig(), rootCmd.Flag("serviceName").Value.String())
		},
	}

	var clientCmd = &cobra.Command{
		Use:   "client",
		Short: "run the process as a client",
		Run: func(subcmd *cobra.Command, args []string) {
			cmd.Client(getConfig(), rootCmd.Flag("serviceName").Value.String())
		},
	}

	rootCmd.AddCommand(clientCmd, serverCmd)
	_ = rootCmd.Execute()
}

func getConfig() (zitiCfg *config.Config) {
	identityJson := rootCmd.Flag("identity").Value.String()
	zitiCfg, err := config.NewFromFile(identityJson)
	if err != nil {
		log.Fatalf("failed to load ziti configuration file: %v", err)
	}
	zitiCfg.ConfigTypes = []string{
		"ziti-tunneler-client.v1",
	}
	return zitiCfg
}
