/*
Copyright © 2021 NAME HERE <EMAIL ADDRESS>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"fmt"
	"github.com/michaelquigley/pfxlog"
	"github.com/openziti/sdk-golang/ziti"
	"github.com/openziti/sdk-golang/ziti/config"
	"github.com/openziti/sdk-golang/ziti/edge"
	"github.com/sirupsen/logrus"
	"net"
	"os"
	"time"

	"github.com/spf13/cobra"
)

func handlePing(conn net.Conn) {
	for {
		buf := make([]byte, 1500)
		n, err := conn.Read(buf)
		if err != nil {
			_ = conn.Close()
			return
		}
		msg := buf[:n]
		if _, err := conn.Write(msg); err != nil {
			logrus.WithError(err).Error("failed to write. closing connection")
			_ = conn.Close()
		}
	}
}

// serverCmd represents the server command
var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "zping client command",
	Long: `This command runs zping in server mode which responds to ziti probe
	messages which are sent to it's associated ziti identity by zping clients`,
	Run: func(cmd *cobra.Command, args []string) {
		sflag, _ := cmd.Flags().GetString("service")
		cflag, _ := cmd.Flags().GetString("config")
		var service string
		if len(sflag) > 0 {
			service = sflag
		} else {
			service = "ziti-ping"
		}
		logger := pfxlog.Logger()
		options := ziti.ListenOptions{
			ConnectTimeout:        10 * time.Second,
			MaxConnections:        3,
			BindUsingEdgeIdentity: true,
		}
		logger.Infof("binding service %v\n", service)
		var listener edge.Listener
		if len(cflag) > 0 {
			file := cflag
			configFile, err := config.NewFromFile(file)
			if err != nil {
				logrus.WithError(err).Error("Error loading config file")
				os.Exit(1)
			}
			context := ziti.NewContextWithConfig(configFile)
			identity, err := context.GetCurrentIdentity()
			if err != nil {
				logrus.WithError(err).Error("Error resolving local Identity")
				os.Exit(1)
			}
			fmt.Printf("\n%+v now serving\n\n", identity.Name)
			listener, err = context.ListenWithOptions(service, &options)
			if err != nil {
				logrus.WithError(err).Error("Error Binding Service")
				os.Exit(1)
			}
		} else {
			context := ziti.NewContext()
			identity, err := context.GetCurrentIdentity()
			if err != nil {
				logrus.WithError(err).Error("Error resolving local Identity")
				os.Exit(1)
			}
			fmt.Printf("\n%+v now serving\n\n", identity.Name)
			listener, err = context.ListenWithOptions(service, &options)
			if err != nil {
				logrus.WithError(err).Error("Error Binding Service")
				os.Exit(1)
			}
		}

		for {
			conn, err := listener.Accept()
			if err != nil {
				logrus.WithError(err).Error("Problem accepting connection, sleeping for 5 Seconds")
				time.Sleep(time.Duration(5) * time.Second)
			}
			logger.Infof("new connection")
			fmt.Println()
			go handlePing(conn)
		}
	},
}

func init() {
	rootCmd.AddCommand(serverCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// serverCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// serverCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	serverCmd.Flags().StringP("service", "s", "ziti-ping", "Name of Service")
	serverCmd.Flags().StringP("config", "c", "", "Name of config file")
}
